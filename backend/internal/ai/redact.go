package ai

import (
	"net/url"
	"regexp"
)

var (
	webURL           = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"']+`)
	shortCode        = regexp.MustCompile(`\b[0-9]{4,8}\b`)
	secretAssignment = regexp.MustCompile(`(?i)\b(password|passcode|otp|one[- ]time code|verification code|access token|api key|secret)["\']?\s*(?::|=|\bis\b|\bwas\b)\s*(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)`)
	bearerCredential = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`)
	jwtCredential    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?\b`)
	emailAddress     = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	phoneNumber      = regexp.MustCompile(`(?:\+?\d[\d(). -]{7,}\d)`)
	accountNumber    = regexp.MustCompile(`(?i)\b((?:account|card|ssn|social security)(?:\s+(?:number|no))?\s*[:#]?\s*)[\d -]{4,}\d\b`)
	urlSecretQuery   = regexp.MustCompile(`(?i)([?&](?:token|access_token|refresh_token|session|sid|password|passwd|otp|code|api_key|key)=)[^&#\s]+`)
)

// RedactSecrets removes common credentials and direct personal identifiers before
// provider transmission. It is intentionally conservative; it is not DLP.
func RedactSecrets(value string) string {
	value = webURL.ReplaceAllStringFunc(value, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return "[REDACTED_URL]"
		}
		if u.User != nil {
			u.User = url.User("REDACTED")
		}
		if u.RawQuery != "" || u.ForceQuery {
			u.RawQuery = "redacted"
			u.ForceQuery = false
		}
		if u.Fragment != "" {
			u.Fragment = "REDACTED"
			u.RawFragment = ""
		}
		return u.String()
	})
	value = secretAssignment.ReplaceAllString(value, "$1=[REDACTED]")
	value = bearerCredential.ReplaceAllString(value, "Bearer [REDACTED]")
	value = jwtCredential.ReplaceAllString(value, "[REDACTED_TOKEN]")
	value = accountNumber.ReplaceAllString(value, "$1[REDACTED]")
	value = emailAddress.ReplaceAllString(value, "[REDACTED_EMAIL]")
	value = phoneNumber.ReplaceAllString(value, "[REDACTED_PHONE]")
	return shortCode.ReplaceAllString(urlSecretQuery.ReplaceAllString(value, "$1[REDACTED]"), "[REDACTED_CODE]")
}
