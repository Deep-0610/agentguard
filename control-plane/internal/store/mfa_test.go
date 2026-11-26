package store

import (
	"bytes"
	"testing"
	"time"
)

func TestTOTPValidationAndReplayProtection(t *testing.T) {
	secret,err:=generateTOTPSecret()
	if err!=nil{t.Fatal(err)}
	now:=time.Date(2026,11,19,12,0,0,0,time.UTC)
	code,step,err:=totpAt(secret,now)
	if err!=nil{t.Fatal(err)}
	if got,ok:=validateTOTP(secret,code,now,step-1);!ok||got!=step{t.Fatalf("expected valid TOTP, got step=%d valid=%t",got,ok)}
	if _,ok:=validateTOTP(secret,code,now,step);ok{t.Fatal("a TOTP step must not be reusable")}
	if _,ok:=validateTOTP(secret,"12x456",now,step-1);ok{t.Fatal("non-numeric TOTP must be rejected")}
	if _,ok:=validateTOTP(secret,"12345",now,step-1);ok{t.Fatal("short TOTP must be rejected")}
}

func TestMFASecretEncryptionIsTenantAndKeyBound(t *testing.T) {
	s:=&Store{pepper:[]byte("0123456789abcdef0123456789abcdef")}
	ciphertext,err:=s.encryptMFASecret("tenant-a","key-a","JBSWY3DPEHPK3PXP")
	if err!=nil{t.Fatal(err)}
	if bytes.Contains(ciphertext,[]byte("JBSWY3DPEHPK3PXP")){t.Fatal("MFA secret was stored in plaintext")}
	plain,err:=s.decryptMFASecret("tenant-a","key-a",ciphertext)
	if err!=nil||plain!="JBSWY3DPEHPK3PXP"{t.Fatalf("could not decrypt MFA secret: %q %v",plain,err)}
	if _,err=s.decryptMFASecret("tenant-b","key-a",ciphertext);err==nil{t.Fatal("ciphertext must be bound to tenant ID")}
	if _,err=s.decryptMFASecret("tenant-a","key-b",ciphertext);err==nil{t.Fatal("ciphertext must be bound to API key ID")}
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri:=TOTPProvisioningURI("AgentGuard","security-owner","JBSWY3DPEHPK3PXP")
	for _,part:=range []string{"otpauth://totp/","secret=JBSWY3DPEHPK3PXP","issuer=AgentGuard","digits=6","period=30"}{
		if !bytes.Contains([]byte(uri),[]byte(part)){t.Fatalf("provisioning URI missing %q: %s",part,uri)}
	}
}
