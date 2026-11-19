package api

import "regexp"

var secretValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{20,}`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|token)\s*[:=]\s*["']?[^\s"'&,;]{8,}`),
	regexp.MustCompile(`(?i)(https?://)[^/@\s:]+:[^/@\s]+@`),
	regexp.MustCompile(`(?i)([?&](?:api[_-]?key|access[_-]?token|token|client[_-]?secret|password)=)[^&\s]+`),
}

func redactUntrusted(value string)string{
	for _,pattern:=range secretValuePatterns{
		if pattern.MatchString(value){
			if pattern.String()==`(?i)(https?://)[^/@\s:]+:[^/@\s]+@`{
				value=pattern.ReplaceAllString(value,"$1[REDACTED]@")
			}else if pattern.String()==`(?i)([?&](?:api[_-]?key|access[_-]?token|token|client[_-]?secret|password)=)[^&\s]+`{
				value=pattern.ReplaceAllString(value,"$1[REDACTED]")
			}else{
				value=pattern.ReplaceAllString(value,"[REDACTED]")
			}
		}
	}
	return value
}
