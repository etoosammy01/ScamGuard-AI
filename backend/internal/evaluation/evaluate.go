// Package evaluation measures a small synthetic corpus; results are not population accuracy.
package evaluation

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/ai"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/detection"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/services"
)

//go:embed testdata/synthetic.json
var corpus []byte

type Case struct{ ID, Kind, Label, Group, Input string }
type Result struct {
	ID        string `json:"id"`
	Expected  string `json:"expected"`
	Predicted string `json:"predicted"`
	Score     int    `json:"score"`
	RiskLevel string `json:"risk_level"`
	Category  string `json:"category"`
}
type Metrics struct {
	DatasetSize         int      `json:"dataset_size"`
	Positive            int      `json:"positive"`
	Negative            int      `json:"negative"`
	Ambiguous           int      `json:"ambiguous"`
	TP                  int      `json:"tp"`
	FP                  int      `json:"fp"`
	TN                  int      `json:"tn"`
	FN                  int      `json:"fn"`
	Precision           float64  `json:"precision"`
	Recall              float64  `json:"recall"`
	F1                  float64  `json:"f1"`
	RiskConsistent      bool     `json:"risk_consistent"`
	MockHybridPreserved int      `json:"mock_hybrid_preserved"`
	Cases               []Result `json:"cases"`
}

func Load() ([]Case, error) {
	var cases []Case
	err := json.Unmarshal(corpus, &cases)
	return cases, err
}

type neutralAnalyzer struct{}

func (neutralAnalyzer) Analyze(context.Context, string, string, []models.Indicator) (ai.Assessment, ai.Usage, error) {
	return ai.Assessment{Category: ai.CategoryUnknown, RiskScore: 0, Confidence: ai.ConfidenceLow, Explanation: "Synthetic neutral mock; not AI quality evaluation.", Indicators: []ai.Indicator{}, Recommendations: []string{}}, ai.Usage{}, nil
}
func Run() (Metrics, error) {
	cases, err := Load()
	if err != nil {
		return Metrics{}, err
	}
	m := Metrics{DatasetSize: len(cases), RiskConsistent: true, Cases: []Result{}}
	for _, c := range cases {
		var r models.ScanResult
		if c.Kind == "url" {
			r, err = detection.AnalyzeURL(c.Input)
		} else {
			r = detection.AnalyzeMessage(c.Input)
		}
		if err != nil {
			return m, fmt.Errorf("case %s: %w", c.ID, err)
		}
		predicted := "negative"
		if r.RiskScore >= 25 {
			predicted = "positive"
		} // Existing low/moderate boundary, not tuned to corpus.
		switch c.Label {
		case "positive":
			m.Positive++
			if predicted == "positive" {
				m.TP++
			} else {
				m.FN++
			}
		case "negative":
			m.Negative++
			if predicted == "positive" {
				m.FP++
			} else {
				m.TN++
			}
		case "ambiguous":
			m.Ambiguous++
		default:
			return m, fmt.Errorf("invalid label")
		}
		m.RiskConsistent = m.RiskConsistent && r.RiskLevel == detection.RiskLevel(r.RiskScore)
		d := services.NewDetection(neutralAnalyzer{}, nil)
		var hybrid models.ScanResult
		if c.Kind == "url" {
			hybrid, err = d.AnalyzeURL(context.Background(), "evaluation", c.Input, "hybrid")
		} else {
			hybrid = d.AnalyzeMessage(context.Background(), "evaluation", c.Input, "hybrid")
		}
		if err != nil {
			return m, err
		}
		if hybrid.RiskScore >= r.RiskScore && hybrid.RuleScore == r.RiskScore {
			m.MockHybridPreserved++
		}
		m.Cases = append(m.Cases, Result{c.ID, c.Label, predicted, r.RiskScore, r.RiskLevel, r.Category})
	}
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	return m, nil
}
