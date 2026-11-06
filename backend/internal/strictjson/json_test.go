package strictjson

import (
	"strings"
	"testing"
)

func TestRejectsAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{`{"name":"one","name":"two"}`, `{"Name":"one","name":"two"}`, `{"na\u006de":"one","name":"two"}`, `{"nested":{"x":1,"x":2}}`, `{} {}`, `null`, `[]`, `{"name":"` + string([]byte{255}) + `"}`, strings.Repeat(`{"x":`, 34) + `0` + strings.Repeat(`}`, 34)} {
		var target struct {
			Name string `json:"name"`
		}
		if Decode([]byte(raw), &target) == nil {
			t.Fatalf("accepted ambiguous JSON: %.80q", raw)
		}
	}
	var target struct {
		Name string `json:"name"`
	}
	if err := Decode([]byte(`{"name":"valid"}`), &target); err != nil || target.Name != "valid" {
		t.Fatal(err)
	}
}

func TestUnicodeCaseEquivalentDuplicateKeys(t *testing.T) {
	for _, raw := range []string{`{"status":"active","ſtatus":"suspended"}`, `{"key":1,"Key":2}`} {
		var value struct {
			Status string `json:"status"`
			Key    int    `json:"key"`
		}
		if err := Decode([]byte(raw), &value); err == nil {
			t.Fatal("Unicode case-fold duplicate accepted")
		}
	}
}
