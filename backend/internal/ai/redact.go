package ai

import (
	"regexp"
)

var (
	secretAssignment = regexp.MustCompile(`(?i)\b(password|passcode|otp|one[- ]time code|verification code|access token|api key|secret)\s*[:=]\s*[^\s,;]+`)
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
	value = secretAssignment.ReplaceAllString(value, "$1=[REDACTED]")
	value = bearerCredential.ReplaceAllString(value, "Bearer [REDACTED]")
	value = jwtCredential.ReplaceAllString(value, "[REDACTED_TOKEN]")
	value = accountNumber.ReplaceAllString(value, "$1[REDACTED]")
	value = emailAddress.ReplaceAllString(value, "[REDACTED_EMAIL]")
	value = phoneNumber.ReplaceAllString(value, "[REDACTED_PHONE]")
	return urlSecretQuery.ReplaceAllString(value, "$1[REDACTED]")
}
