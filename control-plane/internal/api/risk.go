package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Deep-0610/agentguard/control-plane/internal/store"
)

func assessAsset(asset store.AssetInput) (int, []store.FindingInput) {
	scopes:=make([]string,0,len(asset.Scopes))
	for _,scope:=range asset.Scopes { scopes=append(scopes,strings.ToLower(strings.TrimSpace(scope))) }
	hasPrivilege:=false
	hasMailSend:=false
	hasDBRead:=false
	for _,scope:=range scopes {
		if strings.Contains(scope,"admin")||strings.Contains(scope,"write")||strings.Contains(scope,"manage")||strings.Contains(scope,"full_access") { hasPrivilege=true }
		if strings.Contains(scope,"mail.send")||strings.Contains(scope,"email.send")||strings.Contains(scope,"external_email") { hasMailSend=true }
		if strings.Contains(scope,"database.read")||strings.Contains(scope,"db.read")||strings.Contains(scope,"rds.read") { hasDBRead=true }
	}
	var findings []store.FindingInput
	score:=0
	add:=func(rule,severity,confidence,title,description,remediation string,value int){
		fingerprint:=sha256.Sum256([]byte(asset.Source+":"+asset.ExternalID+":"+rule))
		findings=append(findings,store.FindingInput{
			Fingerprint:hex.EncodeToString(fingerprint[:]),RuleID:rule,Severity:severity,Confidence:confidence,
			Category:"identity-risk",Title:title,Description:description,Resource:asset.Name,
			Evidence:"Rule matched normalized inventory metadata; no credential value is stored.",
			Remediation:remediation,
		})
		if value>score { score=value }
	}
	if (asset.OwnerStatus=="SUSPENDED"||asset.OwnerStatus=="UNKNOWN")&&hasPrivilege {
		add("nhi.orphaned-privileged-identity","critical","high","Privileged identity has no active verified owner",
			"The identity has write/admin-like permissions while its owner is suspended or unknown.",
			"Assign a verified active owner or remove unnecessary privileges after review.",95)
	}
	if hasMailSend&&hasDBRead {
		add("nhi.toxic-permission-combination","critical","high","Toxic permission combination detected",
			"The identity combines external email capability with database read access, increasing the impact of misuse.",
			"Separate duties across identities and constrain each tool to the minimum required permissions.",98)
	}
	if asset.Kind=="oauth_app"&&!asset.Verified {
		add("nhi.unverified-oauth-application","high","medium","Unverified OAuth application",
			"The OAuth application is not marked as verified in the source inventory.",
			"Validate publisher, business owner, requested scopes, and application provenance.",78)
	}
	if asset.Kind=="api_token"&&asset.SecretAgeDays>90 {
		add("nhi.stale-api-token","medium","high","API token exceeds 90-day rotation target",
			"The token age exceeds the configured 90-day review threshold.",
			"Rotate the token using the provider's supported workflow and shorten its lifetime.",55)
	}
	if score==0&&asset.OwnerStatus=="UNKNOWN" { score=30 }
	return score,findings
}
