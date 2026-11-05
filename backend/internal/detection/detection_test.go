package detection

import (
	"strings"
	"testing"
)

func TestBenignUrgencyAndCombinedMessage(t *testing.T) {
	benign := AnalyzeMessage("URGENT: The meeting starts in ten minutes. Please join the call.")
	if benign.RiskScore > 5 || benign.RiskLevel != "low" {
		t.Fatalf("urgency alone over-scored: %+v", benign)
	}
	scam := AnalyzeMessage("URGENT: Your bank account has been suspended. Verify your password now at https://secure-login.invalid/verify")
	if scam.RiskScore < 50 || scam.Category != "credential_theft" || len(scam.Indicators) < 3 {
		t.Fatalf("combined scam missed: %+v", scam)
	}
	if scam.ScanType != "message" || scam.AnalysisMode != "rules" {
		t.Fatal(scam)
	}
}
func TestMessageCategoriesAndLinks(t *testing.T) {
	fixtures := []struct{ body, category string }{{"Congratulations, you won a prize! Pay a processing fee to claim your prize.", "fake_prize"}, {"Guaranteed returns! Double your money, wire transfer today.", "investment_scam"}, {"Remote job offer: pay a registration fee today.", "job_scam"}, {"Delivery failed; pay a redelivery fee at https://tinyurl.com/parcel", "delivery_scam"}, {"Move to WhatsApp and send your OTP.", "credential_theft"}}
	for _, f := range fixtures {
		r := AnalyzeMessage(f.body)
		if r.Category != f.category {
			t.Errorf("wanted %s, got %s %+v", f.category, r.Category, r)
		}
	}
}
func TestURLRules(t *testing.T) {
	fixtures := []struct{ url, id string }{{"https://user:pw@example.com/login", "url_userinfo"}, {"https://xn--e1afmkfd.example/login", "punycode_hostname"}, {"https://paypal-example.com/login", "brand_domain_mimic"}, {"https://login.paypal.example.net/verify", "brand_in_subdomain"}, {"https://example.com:8443/a", "nonstandard_port"}, {"https://bit.ly/abc", "url_shortener"}, {"https://example.com/" + strings.Repeat("a", 220), "long_url"}}
	for _, f := range fixtures {
		r, err := AnalyzeURL(f.url)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, i := range r.Indicators {
			if i.RuleID == f.id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing %s: %+v", f.url, f.id, r)
		}
	}
}
func TestInvalidURLs(t *testing.T) {
	for _, raw := range []string{"", "http:///path", "javascript:alert(1)", "file:///etc/passwd", "https://", "//example.com"} {
		if _, err := AnalyzeURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestWeakURLSignalsAreNotMaliciousVerdicts(t *testing.T) {
	for _, raw := range []string{"https://192.0.2.10/path", "https://bit.ly/short", "https://example.com/" + strings.Repeat("a", 220), "https://xn--e1afmkfd.example/login"} {
		result, err := AnalyzeURL(raw)
		if err != nil {
			t.Fatal(err)
		}
		if result.RiskLevel != "low" || result.Category != "unknown" {
			t.Errorf("weak structural indicator became a malicious verdict for %s: %+v", raw, result)
		}
	}
	ipv6, err := AnalyzeURL("https://[2001:db8::1]/login")
	if err != nil || ipv6.Category != "unknown" {
		t.Fatalf("IPv6 literal should be treated as a weak syntax warning: %+v %v", ipv6, err)
	}
}

func TestMessageDoesNotUseBrandSubstringAsTrustedDomainCheck(t *testing.T) {
	result := AnalyzeMessage("Please review the help page at https://www.paypal.com/signin")
	if result.RiskScore != 0 || len(result.Indicators) != 0 {
		t.Fatalf("ordinary brand mention and official registered domain marked suspicious: %+v", result)
	}
}

func TestCredentialSafetyWarningIsNotMisclassifiedAsCredentialTheft(t *testing.T) {
	result := AnalyzeMessage("Security reminder: never share your password or OTP. We will never ask you to share credentials.")
	if result.Category != "unknown" || result.RiskScore != 0 {
		t.Fatalf("safety notice was misclassified: %+v", result)
	}
}
func TestScoringBoundariesAndCorrelation(t *testing.T) {
	findings := []Finding{{ID: "a", Weight: 30, Group: "same"}, {ID: "b", Weight: 20, Group: "same"}, {ID: "c", Weight: 90, Group: "other"}}
	got, ind := score(findings)
	if got != 100 || len(ind) != 2 {
		t.Fatal(got, ind)
	}
	for n, want := range map[int]string{0: "low", 24: "low", 25: "moderate", 49: "moderate", 50: "high", 74: "high", 75: "critical", 100: "critical"} {
		if RiskLevel(n) != want {
			t.Errorf("%d %s", n, RiskLevel(n))
		}
	}
}
