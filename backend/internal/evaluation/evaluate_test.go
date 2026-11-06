package evaluation

import (
	"testing"
)

func TestCorpusIntegrityAndHybridSafety(t *testing.T) {
	cases, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] || c.Input == "" || c.Kind != "message" && c.Kind != "url" {
			t.Fatal("invalid corpus entry", c.ID)
		}
		seen[c.ID] = true
	}
	m, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	if !m.RiskConsistent || m.MockHybridPreserved != len(cases) || m.TP+m.FN != m.Positive || m.TN+m.FP != m.Negative {
		t.Fatal("evaluation invariants failed")
	}
	t.Logf("N=%d TP=%d FP=%d TN=%d FN=%d precision=%.4f recall=%.4f F1=%.4f", m.DatasetSize, m.TP, m.FP, m.TN, m.FN, m.Precision, m.Recall, m.F1)
}
