package detection

import (
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"net/url"
	"regexp"
	"strings"
)

var sensitivePattern = regexp.MustCompile(`\b(?:passwords?|passcodes?|one[- ]time codes?|verification codes?|otps?|pin numbers?|security codes?|bvn|nin)\b`)

var linkPattern = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>\"']+`)

var officialBrandDomains = map[string][]string{
	"paypal":          {"paypal.com", "paypal.co.uk", "paypal.me"},
	"microsoft":       {"microsoft.com", "microsoftonline.com", "office.com", "live.com"},
	"apple":           {"apple.com", "icloud.com"},
	"amazon":          {"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de"},
	"google":          {"google.com", "google.co.uk"},
	"facebook":        {"facebook.com", "fb.com"},
	"instagram":       {"instagram.com"},
	"netflix":         {"netflix.com"},
	"bank of america": {"bankofamerica.com"},
	"chase":           {"chase.com"},
	"wells fargo":     {"wellsfargo.com"},
	"dhl":             {"dhl.com"},
	"fedex":           {"fedex.com"},
	"ups":             {"ups.com"},
}

func containsAny(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
func AnalyzeMessage(content string) models.ScanResult {
	text := strings.ToLower(content)
	findings := make([]Finding, 0, 8)
	add := func(id, category, description string, weight int, group, scam string, priority int) {
		findings = append(findings, Finding{id, category, description, weight, group, scam, priority})
	}
	urgent := containsAny(text, "urgent", "immediately", "act now", "within 24 hours", "final warning", "limited time", "right away", "do not delay", "suspended today")
	asksSensitive := false
	// A safety notice in one sentence must not suppress a credential request elsewhere.
	clauses := strings.NewReplacer(" but ", ";", " however ", ";").Replace(text)
	for _, clause := range strings.FieldsFunc(clauses, func(r rune) bool { return strings.ContainsRune(".!?;\n", r) }) {
		sensitive := sensitivePattern.MatchString(clause)
		notice := containsAny(clause, "never share", "do not share", "don't share", "no share", "will never ask", "never ask for")
		if sensitive && !notice && containsAny(clause, "send", "share", "provide", "enter", "confirm", "reply with", "give us", "verify your", "tell me", "submit") {
			asksSensitive = true
		}
	}
	impersonation := containsAny(text, "bank", "account security", "security team", "support team", "microsoft support", "apple support", "paypal", "amazon support", "your account")
	bankIdentity := containsAny(text, "bank", "credit union", "bank of america", "chase", "wells fargo", "visa", "mastercard")
	payment := false
	for _, clause := range strings.FieldsFunc(clauses, func(r rune) bool { return strings.ContainsRune(".!?;\n", r) }) {
		if containsAny(clause, "do not send money", "don't send money", "never send money", "no send money") {
			continue
		}
		payment = payment || containsAny(clause, "pay a fee", "processing fee", "release fee", "advance fee", "wire transfer", "gift card", "pay us", "send money", "registration fee", "redelivery fee", "customs fee")
	}
	prize := containsAny(text, "you won", "winner", "congratulations", "claim your prize", "giveaway", "lottery")
	financial := containsAny(text, "guaranteed returns", "risk-free profit", "double your money", "guaranteed profit", "secret investment")
	suspension := containsAny(text, "account suspended", "account will be suspended", "account has been suspended", "account locked", "account will be closed", "unusual sign-in", "verify your account")
	offchannel := containsAny(text, "move to whatsapp", "message me on telegram", "continue on whatsapp", "contact me on signal", "move this conversation")
	job := containsAny(text, "job offer", "remote position", "hiring immediately", "work from home")
	delivery := containsAny(text, "delivery failed", "package held", "customs fee", "redelivery fee", "parcel awaiting")
	hasLink := false
	linkSuspicious := false
	brandLinkMismatch := false
	for _, raw := range linkPattern.FindAllString(content, -1) {
		raw = strings.TrimRight(raw, ".,!?;:)")
		if strings.HasPrefix(strings.ToLower(raw), "www.") {
			raw = "http://" + raw
		}
		u, e := url.Parse(raw)
		if e != nil {
			continue
		}
		host := u.Hostname()
		if host == "" {
			continue
		}
		hasLink = true
		brandLinkMismatch = brandLinkMismatch || messageBrandLinkMismatch(text, raw)
		parsed, err := AnalyzeURL(raw)
		if err == nil {
			for _, indicator := range parsed.Indicators {
				switch indicator.RuleID {
				case "url_userinfo", "ip_literal_host", "punycode_hostname", "brand_domain_mimic", "brand_in_subdomain", "nonstandard_port", "encoded_components":
					linkSuspicious = true
				}
			}
		}
	}
	if asksSensitive {
		add("credential_request", "credential_theft", "The message asks for sensitive authentication information.", 35, "credentials", "credential_theft", 1)
	}
	if urgent && suspension && impersonation {
		add("urgent_impersonation", "social_engineering", "Urgent pressure is combined with an account threat and an apparent organization identity.", 25, "pressure", "phishing", 2)
	}
	if suspension && !urgent {
		add("account_threat", "account_security", "The message threatens account access or service suspension.", 12, "account_threat", "account_takeover", 3)
	}
	if impersonation && hasLink && (linkSuspicious || brandLinkMismatch || suspension || asksSensitive) {
		category := "phishing"
		if bankIdentity {
			category = "bank_impersonation"
		}
		add("organization_link", "impersonation", "An organization or account request is paired with a link that warrants independent verification.", 20, "impersonation", category, 4)
	}
	if linkSuspicious {
		add("suspicious_embedded_link", "suspicious_link", "The message contains a link with an unusual host or user information.", 15, "message_link", "phishing", 5)
	}
	if prize && payment {
		add("prize_fee", "advance_fee", "A prize claim is paired with an upfront payment request.", 35, "payment_demand", "fake_prize", 6)
	}
	if payment && !prize && !job && !financial && !delivery {
		add("advance_fee", "advance_fee", "The message requests an upfront fee or irreversible payment.", 30, "payment_demand", "advance_fee", 7)
	}
	if financial && payment {
		add("investment_payment", "investment_scam", "An investment promise is paired with a request to transfer money.", 30, "financial_offer", "investment_scam", 8)
	} else if financial {
		add("financial_promise", "investment_scam", "The message promises unusually certain or risk-free financial returns.", 18, "financial_offer", "investment_scam", 9)
	}
	if offchannel {
		add("off_channel_migration", "channel_change", "The sender urges moving the conversation to a separate messaging channel.", 15, "channel_change", "general_social_engineering", 10)
	}
	if job && containsAny(text, "pay a fee", "processing fee", "registration fee", "send money") {
		add("job_upfront_fee", "job_scam", "A job opportunity is paired with a fee or payment request.", 25, "job_offer", "job_scam", 11)
	}
	if delivery && (hasLink || payment) {
		add("delivery_link", "delivery_scam", "A delivery problem is paired with a payment request or embedded link.", 20, "delivery_notice", "delivery_scam", 12)
	}
	if urgent && !suspension && !asksSensitive && !payment && !prize && !hasLink {
		add("urgency_only", "context", "The message uses urgency, but no additional strong scam signal was found.", 3, "urgency", "", 13)
	}
	return buildResult("message", findings)
}

func messageBrandLinkMismatch(text, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if idnaHost, err := idna.Lookup.ToASCII(host); err == nil {
		host = strings.ToLower(idnaHost)
	}
	registered, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return true
	}
	mentioned := false
	for brand, domains := range officialBrandDomains {
		pattern := regexp.MustCompile(`(?:^|[^a-z0-9])` + regexp.QuoteMeta(brand) + `(?:$|[^a-z0-9])`)
		if !pattern.MatchString(text) {
			continue
		}
		mentioned = true
		for _, domain := range domains {
			if registered == domain {
				return false
			}
		}
	}
	return mentioned
}
