package services

import (
	"errors"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid input")

func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) < 3 || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		return "", ErrInvalid
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
		return "", ErrInvalid
	}
	// Restrict to unambiguous ASCII mailbox syntax; IDN domains should be supplied as punycode.
	for _, r := range email {
		if r > 127 || unicode.IsSpace(r) {
			return "", ErrInvalid
		}
	}
	return email, nil
}
func ValidateName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 200 {
		return "", ErrInvalid
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrInvalid
		}
	}
	return name, nil
}
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 1024 {
		return ErrInvalid
	}
	return nil
}
func ValidateBio(bio string) error {
	if !utf8.ValidString(bio) || utf8.RuneCountInString(bio) > 500 {
		return ErrInvalid
	}
	for _, r := range bio {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ErrInvalid
		}
	}
	return nil
}
