package detection

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLSyntaxAndNoNetwork(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "javascript:alert(1)", "ftp://example.invalid", "https://exa_mple.invalid", "https://a..invalid", "https://-bad.invalid", "https://example.invalid:65536", "https://example.invalid:0", "https://example.invalid/\\evil", "https://example.invalid/\u202esecret", "https://example.invalid/\n", "https://" + strings.Repeat("a", 64) + ".invalid", "https://example.invalid/" + strings.Repeat("x", 2048)} {
		if _, err := AnalyzeURL(raw); err == nil {
			t.Errorf("invalid URL accepted: %.100q", raw)
		}
	}
	var calls atomic.Int64
	old := http.DefaultTransport
	http.DefaultTransport = denyTransport{calls: &calls}
	defer func() { http.DefaultTransport = old }()
	for _, raw := range []string{"http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/", "https://EXAMPLE.invalid./", "https://bücher.invalid/", "https://paypal.com@other.invalid/", "https://example.invalid/%2540"} {
		if _, err := AnalyzeURL(raw); err != nil {
			t.Errorf("valid lexical URL rejected %q: %v", raw, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("URL scanning made network requests")
	}
}

type denyTransport struct{ calls *atomic.Int64 }

func (d denyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	panic("scanner attempted network I/O")
}
func TestSafetyNoticeDoesNotSuppressSeparateTheftRequest(t *testing.T) {
	for _, text := range []string{"Never share your password. Send your OTP to this agent now.", "We will never ask for your password but please submit your OTP here."} {
		r := AnalyzeMessage(text)
		found := false
		for _, i := range r.Indicators {
			found = found || i.RuleID == "credential_request"
		}
		if !found {
			t.Fatal("credential request suppressed")
		}
	}
	benign := AnalyzeMessage("Abeg no share your OTP. Our bank will never ask you to share your OTP or password.")
	for _, i := range benign.Indicators {
		if i.RuleID == "credential_request" {
			t.Fatal("safety advice flagged as credential theft")
		}
	}
	text := "PayPal and DHL: see https://paypal.com/help"
	first := AnalyzeMessage(text).RiskScore
	for i := 0; i < 200; i++ {
		if AnalyzeMessage(text).RiskScore != first {
			t.Fatal("nondeterministic brand matching")
		}
	}
}
func TestModestLocalConcurrentScanLoad(t *testing.T) {
	start := time.Now()
	done := make(chan bool, 8)
	for worker := 0; worker < 8; worker++ {
		go func() {
			for i := 0; i < 25; i++ {
				r := AnalyzeMessage("Urgent bank notice: send your OTP to verify your account.")
				if r.RiskScore < 25 {
					done <- false
					return
				}
			}
			done <- true
		}()
	}
	for i := 0; i < 8; i++ {
		if !<-done {
			t.Fatal("inconsistent concurrent scan")
		}
	}
	t.Logf("200 message scans, 8 workers: %s", time.Since(start))
}
func FuzzURLParser(f *testing.F) {
	for _, s := range []string{"https://example.invalid", "http://[::1]", "https://bücher.invalid", "http://a@b.invalid"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, e := AnalyzeURL(s)
		if e == nil && (r.RiskScore < 0 || r.RiskScore > 100 || r.RiskLevel != RiskLevel(r.RiskScore)) {
			t.Fatal("invalid risk output")
		}
	})
}

func TestNegativePaymentAdviceIsNotAnUpfrontFeeRequest(t *testing.T) {
	if got := AnalyzeMessage("Do not send money to strangers claiming you won a lottery."); got.RiskScore >= 25 {
		t.Fatal("negative safety advice flagged", got.RiskScore)
	}
	if got := AnalyzeMessage("Do not send money to strangers. You won a lottery. Pay a processing fee to claim."); got.RiskScore < 25 {
		t.Fatal("separate malicious demand suppressed")
	}
}

func TestIdentityKeywordsHaveWordBoundaries(t *testing.T) {
	for _, message := range []string{"Please send the morning agenda.", "Share the planning document after the meeting.", "Please provide the hotpot recipe."} {
		for _, indicator := range AnalyzeMessage(message).Indicators {
			if indicator.RuleID == "credential_request" {
				t.Fatal("substring treated as credential", message)
			}
		}
	}
}
