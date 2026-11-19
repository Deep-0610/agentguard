package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrMFARequired = fmt.Errorf("MFA enrollment is required")
var ErrMFAInvalid = fmt.Errorf("MFA code is invalid or has already been used")
var ErrMFALocked = fmt.Errorf("MFA verification is temporarily locked")

func mfaEncryptionKey(pepper []byte) []byte {
	mac:=hmac.New(sha256.New,pepper)
	_,_=mac.Write([]byte("agentguard:mfa:totp:v1"))
	return mac.Sum(nil)
}

func (s *Store) encryptMFASecret(tenantID,keyID,secret string)([]byte,error){
	block,err:=aes.NewCipher(mfaEncryptionKey(s.pepper));if err!=nil{return nil,err}
	gcm,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
	nonce:=make([]byte,gcm.NonceSize());if _,err=rand.Read(nonce);err!=nil{return nil,err}
	aad:=[]byte(tenantID+":"+keyID)
	return append(nonce,gcm.Seal(nil,nonce,[]byte(secret),aad)...),nil
}

func (s *Store) decryptMFASecret(tenantID,keyID string,ciphertext []byte)(string,error){
	block,err:=aes.NewCipher(mfaEncryptionKey(s.pepper));if err!=nil{return "",err}
	gcm,err:=cipher.NewGCM(block);if err!=nil{return "",err}
	if len(ciphertext)<gcm.NonceSize(){return "",fmt.Errorf("stored MFA secret is malformed")}
	nonce:=ciphertext[:gcm.NonceSize()]
	plain,err:=gcm.Open(nil,nonce,ciphertext[gcm.NonceSize():],[]byte(tenantID+":"+keyID))
	if err!=nil{return "",fmt.Errorf("decrypt MFA secret: %w",err)}
	return string(plain),nil
}

func generateTOTPSecret()(string,error){
	raw:=make([]byte,20)
	if _,err:=rand.Read(raw);err!=nil{return "",err}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw),nil
}

func totpAt(secret string,at time.Time)(string,int64,error){
	key,err:=base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err!=nil{return "",0,err}
	step:=at.Unix()/30
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:],uint64(step))
	mac:=hmac.New(sha1.New,key);_,_=mac.Write(counter[:]);sum:=mac.Sum(nil)
	offset:=sum[len(sum)-1]&0x0f
	value:=(uint32(sum[offset])&0x7f)<<24|(uint32(sum[offset+1])&0xff)<<16|(uint32(sum[offset+2])&0xff)<<8|(uint32(sum[offset+3])&0xff)
	code:=fmt.Sprintf("%06d",value%1000000)
	return code,step,nil
}

func validateTOTP(secret,code string,now time.Time,lastUsedStep int64)(int64,bool){
	if len(code)!=6{return 0,false}
	for _,r:=range code{if r<'0'||r>'9'{return 0,false}}
	current:=now.Unix()/30
	for offset:=int64(-1);offset<=1;offset++{
		step:=current+offset
		if step<=lastUsedStep{continue}
		expected,_,err:=totpAt(secret,time.Unix(step*30,0))
		if err==nil&&subtle.ConstantTimeCompare([]byte(expected),[]byte(code))==1{return step,true}
	}
	return 0,false
}

func (s *Store) BeginTOTPEnrollment(ctx context.Context,p Principal)(string,error){
	secret,err:=generateTOTPSecret();if err!=nil{return "",err}
	ciphertext,err:=s.encryptMFASecret(p.TenantID,p.KeyID,secret);if err!=nil{return "",err}
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return "",err};defer tx.Rollback()
	var enabled bool
	err=tx.QueryRowContext(ctx,`SELECT mfa_enabled FROM api_keys WHERE tenant_id=$1 AND key_id=$2 AND revoked_at IS NULL FOR UPDATE`,p.TenantID,p.KeyID).Scan(&enabled)
	if err==sql.ErrNoRows{return "",ErrNotFound};if err!=nil{return "",err}
	if enabled{return "",fmt.Errorf("MFA is already enabled; contact an administrator for recovery")}
	if _,err=tx.ExecContext(ctx,`UPDATE api_keys SET mfa_secret_ciphertext=$3,mfa_last_used_step=0,mfa_failed_attempts=0,mfa_locked_until=NULL,mfa_verified_at=NULL WHERE tenant_id=$1 AND key_id=$2`,p.TenantID,p.KeyID,ciphertext);err!=nil{return "",err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"mfa.totp.enrollment_started","api_key",p.KeyID,p.RequestID,map[string]any{"method":"totp"});err!=nil{return "",err}
	if err=tx.Commit();err!=nil{return "",err}
	return secret,nil
}

func (s *Store) ConfirmTOTP(ctx context.Context,p Principal,code string)error{
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	var ciphertext []byte;var enabled bool;var lastStep int64;var attempts int;var locked sql.NullTime
	err=tx.QueryRowContext(ctx,`SELECT mfa_secret_ciphertext,mfa_enabled,mfa_last_used_step,mfa_failed_attempts,mfa_locked_until FROM api_keys WHERE tenant_id=$1 AND key_id=$2 AND revoked_at IS NULL FOR UPDATE`,p.TenantID,p.KeyID).Scan(&ciphertext,&enabled,&lastStep,&attempts,&locked)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if enabled{return fmt.Errorf("MFA is already enabled")}
	if len(ciphertext)==0{return ErrMFARequired}
	now:=time.Now()
	if locked.Valid&&locked.Time.After(now){return ErrMFALocked}
	secret,err:=s.decryptMFASecret(p.TenantID,p.KeyID,ciphertext);if err!=nil{return err}
	step,valid:=validateTOTP(secret,code,now,lastStep)
	if !valid{
		attempts++
		var lockUntil any
		if attempts>=5{lockUntil=now.Add(15*time.Minute);attempts=5}
		if _,err=tx.ExecContext(ctx,`UPDATE api_keys SET mfa_failed_attempts=$3,mfa_locked_until=$4 WHERE tenant_id=$1 AND key_id=$2`,p.TenantID,p.KeyID,attempts,lockUntil);err!=nil{return err}
		if err=tx.Commit();err!=nil{return err}
		if attempts>=5{return ErrMFALocked}
		return ErrMFAInvalid
	}
	if _,err=tx.ExecContext(ctx,`UPDATE api_keys SET mfa_enabled=true,mfa_verified_at=now(),mfa_last_used_step=$3,mfa_failed_attempts=0,mfa_locked_until=NULL WHERE tenant_id=$1 AND key_id=$2`,p.TenantID,p.KeyID,step);err!=nil{return err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"mfa.totp.enabled","api_key",p.KeyID,p.RequestID,map[string]any{"method":"totp"});err!=nil{return err}
	return tx.Commit()
}

func (s *Store) MFAStatus(ctx context.Context,p Principal)(bool,error){
	var enabled bool
	err:=s.db.QueryRowContext(ctx,`SELECT mfa_enabled FROM api_keys WHERE tenant_id=$1 AND key_id=$2 AND revoked_at IS NULL`,p.TenantID,p.KeyID).Scan(&enabled)
	if err==sql.ErrNoRows{return false,ErrNotFound}
	return enabled,err
}

func (s *Store) RevokeAPIKey(ctx context.Context,p Principal,id,code string)error{
	tx,err:=s.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
	var tenantLock string
	if err=tx.QueryRowContext(ctx,`SELECT id::text FROM tenants WHERE id=$1 FOR UPDATE`,p.TenantID).Scan(&tenantLock);err!=nil{return err}
	var ciphertext []byte;var enabled bool;var lastStep int64;var attempts int;var locked sql.NullTime
	err=tx.QueryRowContext(ctx,`SELECT mfa_secret_ciphertext,mfa_enabled,mfa_last_used_step,mfa_failed_attempts,mfa_locked_until FROM api_keys WHERE tenant_id=$1 AND key_id=$2 AND revoked_at IS NULL FOR UPDATE`,p.TenantID,p.KeyID).Scan(&ciphertext,&enabled,&lastStep,&attempts,&locked)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if !enabled||len(ciphertext)==0{return ErrMFARequired}
	now:=time.Now()
	if locked.Valid&&locked.Time.After(now){return ErrMFALocked}
	secret,err:=s.decryptMFASecret(p.TenantID,p.KeyID,ciphertext);if err!=nil{return err}
	step,valid:=validateTOTP(secret,code,now,lastStep)
	if !valid{
		attempts++
		var lockUntil any
		if attempts>=5{lockUntil=now.Add(15*time.Minute);attempts=5}
		if _,err=tx.ExecContext(ctx,`UPDATE api_keys SET mfa_failed_attempts=$3,mfa_locked_until=$4 WHERE tenant_id=$1 AND key_id=$2`,p.TenantID,p.KeyID,attempts,lockUntil);err!=nil{return err}
		if err=tx.Commit();err!=nil{return err}
		if attempts>=5{return ErrMFALocked}
		return ErrMFAInvalid
	}
	if _,err=tx.ExecContext(ctx,`UPDATE api_keys SET mfa_last_used_step=$3,mfa_failed_attempts=0,mfa_locked_until=NULL WHERE tenant_id=$1 AND key_id=$2`,p.TenantID,p.KeyID,step);err!=nil{return err}
	var targetRole string
	err=tx.QueryRowContext(ctx,`SELECT role FROM api_keys WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL FOR UPDATE`,p.TenantID,id).Scan(&targetRole)
	if err==sql.ErrNoRows{return ErrNotFound};if err!=nil{return err}
	if targetRole=="owner"{
		var owners int
		if err=tx.QueryRowContext(ctx,`SELECT count(*) FROM api_keys WHERE tenant_id=$1 AND role='owner' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`,p.TenantID).Scan(&owners);err!=nil{return err}
		if owners<=1{return fmt.Errorf("cannot revoke the last active owner key")}
	}
	if _,err=tx.ExecContext(ctx,`UPDATE api_keys SET revoked_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`,p.TenantID,id);err!=nil{return err}
	if err=appendAudit(ctx,tx,p.TenantID,p.KeyID,p.Role,"api_key.revoked","api_key",id,p.RequestID,map[string]any{"target_role":targetRole,"mfa":"totp"});err!=nil{return err}
	return tx.Commit()
}

func TOTPProvisioningURI(issuer,account,secret string)string{
	label:=url.PathEscape(issuer+":"+account)
	query:=url.Values{"secret":{secret},"issuer":{issuer},"algorithm":{"SHA1"},"digits":{"6"},"period":{"30"}}
	return "otpauth://totp/"+label+"?"+query.Encode()
}

func TOTPCodeForTest(secret string,at time.Time)(string,int64,error){return totpAt(secret,at)}
func ParseTOTPCode(code string)int{n,_:=strconv.Atoi(code);return n}
var _ = hex.EncodeToString
