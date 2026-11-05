package services

import (
	"context"
	"strings"
	"testing"
)

func TestPasswords(t *testing.T) {
	p, err := NewPasswords()
	if err != nil {
		t.Fatal(err)
	}
	password := "correct horse battery staple 🔐"
	hash, err := p.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == second || strings.Contains(hash, password) || !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatal("unsafe hash format or salt")
	}
	for _, tt := range []struct {
		password, hash string
		want           bool
	}{{password, hash, true}, {"wrong password", hash, false}, {password, "$argon2id$v=19$m=999999999,t=9999,p=1$x$x", false}, {password, "malformed", false}} {
		valid, err := p.Verify(context.Background(), tt.password, tt.hash)
		if err != nil || valid != tt.want {
			t.Fatalf("verification mismatch %v %v", valid, err)
		}
	}
	p.slots <- struct{}{}
	p.slots <- struct{}{}
	if _, err = p.Hash(context.Background(), password); err != ErrBusy {
		t.Fatal("missing concurrency limit")
	}
	<-p.slots
	<-p.slots
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.Hash(ctx, password); err == nil {
		t.Fatal("ignored cancellation")
	}
}
func TestInputValidation(t *testing.T) {
	email, err := NormalizeEmail("  USER@Example.COM  ")
	if err != nil || email != "user@example.com" {
		t.Fatal(email, err)
	}
	for _, invalid := range []string{"invalid", "a@b\r\nInjected: value", "Name <a@example.com>", strings.Repeat("x", 255) + "@example.com"} {
		if _, err = NormalizeEmail(invalid); err == nil {
			t.Fatalf("accepted invalid email")
		}
	}
	for _, invalid := range []string{"short", strings.Repeat("x", 1025)} {
		if ValidatePassword(invalid) == nil {
			t.Fatal("accepted invalid password")
		}
	}
	if ValidatePassword(strings.Repeat("long passphrase ", 40)) != nil {
		t.Fatal("rejected passphrase")
	}
	if _, err = ValidateName(" \n "); err == nil {
		t.Fatal("accepted empty name")
	}
	if ValidateBio(strings.Repeat("x", 501)) == nil {
		t.Fatal("accepted oversized bio")
	}
}
