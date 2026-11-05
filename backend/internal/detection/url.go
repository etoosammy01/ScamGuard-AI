package detection

import (
	"errors"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/url"
	"strings"
)

var ErrInvalidURL = errors.New("invalid URL")
var shorteners = map[string]bool{"bit.ly": true, "t.co": true, "tinyurl.com": true, "goo.gl": true, "is.gd": true, "buff.ly": true, "ow.ly": true, "cutt.ly": true, "rb.gy": true, "rebrand.ly": true}
var brandTerms = []string{"paypal", "microsoft", "apple", "amazon", "google", "facebook", "instagram", "netflix", "bankofamerica", "chase", "wellsfargo", "dhl", "fedex", "ups"}

func AnalyzeURL(raw string) (models.ScanResult, error) {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil || u == nil || u.Host == "" {
		return models.ScanResult{}, ErrInvalidURL
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return models.ScanResult{}, ErrInvalidURL
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return models.ScanResult{}, ErrInvalidURL
	}
	ascii := host
	if net.ParseIP(host) == nil {
		ascii, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return models.ScanResult{}, ErrInvalidURL
		}
	}
	ascii = strings.ToLower(ascii)
	findings := make([]Finding, 0, 10)
	add := func(id, category, description string, weight int, group, scam string, priority int) {
		findings = append(findings, Finding{id, category, description, weight, group, scam, priority})
	}
	if u.User != nil {
		add("url_userinfo", "url_structure", "The URL contains user information that can obscure its actual destination.", 30, "destination", "phishing", 1)
	}
	if net.ParseIP(ascii) != nil {
		add("ip_literal_host", "url_host", "The URL uses a numeric IP address instead of a registered domain.", 18, "host", "", 2)
	}
	if strings.Contains(ascii, "xn--") {
		add("punycode_hostname", "url_host", "The hostname contains an internationalized punycode label; inspect the displayed domain carefully.", 12, "idn", "", 3)
	}
	labels := strings.Split(ascii, ".")
	if len(labels) > 5 {
		add("deep_subdomains", "url_host", "The hostname has many subdomain levels that can make its registered domain harder to recognize.", 15, "subdomains", "", 4)
	}
	registrable, psErr := publicsuffix.EffectiveTLDPlusOne(ascii)
	if psErr == nil {
		hostLabels := strings.Split(ascii, ".")
		domainLabels := strings.Split(registrable, ".")
		subdomainCount := len(hostLabels) - len(domainLabels)
		registeredDomain := strings.Split(strings.ToLower(registrable), ".")[0]
		for _, brand := range brandTerms {
			if strings.Contains(registeredDomain, brand) && registeredDomain != brand {
				add("brand_domain_mimic", "impersonation", "The registered domain contains a familiar brand name without being that brand’s domain.", 25, "brand_impersonation", "phishing", 6)
			} else if subdomainCount > 0 && subdomainCount <= 5 {
				for _, label := range hostLabels[:subdomainCount] {
					if label == brand {
						add("brand_in_subdomain", "impersonation", "A familiar brand term appears in a subdomain outside that brand’s registered domain.", 28, "brand_impersonation", "phishing", 5)
						break
					}
				}
			}
		}
	} else if net.ParseIP(ascii) == nil {
		return models.ScanResult{}, ErrInvalidURL
	}
	if shorteners[ascii] {
		add("url_shortener", "redirect", "The hostname is a known URL shortening service, so its final destination is not visible here.", 10, "redirect", "", 7)
	}
	if len(trimmed) > 200 {
		add("long_url", "url_structure", "The URL is unusually long, which can make its destination harder to inspect.", 8, "length", "", 8)
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		add("nonstandard_port", "url_structure", "The URL uses a nonstandard web port.", 12, "port", "phishing", 9)
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "%25") || strings.Contains(lower, "%252f") || strings.Contains(lower, "%40") {
		add("encoded_components", "obfuscation", "The URL contains repeated or encoded delimiters that may obscure its structure.", 12, "encoding", "phishing", 10)
	}
	if len(ascii) > 100 {
		add("long_hostname", "url_host", "The hostname is unusually long.", 10, "length", "", 11)
	}
	return buildResult("url", findings), nil
}
