package reports

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
	"github.com/signintech/gopdf"
)

//go:embed NotoSans-Regular.ttf
var font []byte
var ErrLimit = errors.New("report exceeds resource limits")

// Render only persisted fields, never HTML, links, scripts or submitted content.
func Generate(ctx context.Context, scan models.ScanResult, generated time.Time) ([]byte, error) {
	if len(scan.Indicators) > 100 || len(scan.Recommendations) > 50 {
		return nil, ErrLimit
	}
	lines := []string{"ScamGuard AI | Security Report", "Report identifier: SG-" + scan.ScanID, "Scan date (UTC): " + scan.CreatedAt.UTC().Format(time.RFC3339), "Scan type: " + scan.ScanType, fmt.Sprintf("Risk score: %d / 100 | Level: %s", scan.RiskScore, scan.RiskLevel), "Detected category: " + scan.Category, fmt.Sprintf("Rule-based findings | Rule score: %d / 100", scan.RuleScore), scan.Explanation, "AI analysis summary", "Full AI analysis was not retained with this scan. No AI summary is available.", "Analysis mode: " + scan.AnalysisMode + " | AI status: " + scan.AIStatus, "Triggered risk indicators"}
	for _, i := range scan.Indicators {
		lines = append(lines, fmt.Sprintf("%s: %s (+%d)", i.RuleID, i.Description, i.ScoreContribution))
	}
	if len(scan.Indicators) == 0 {
		lines = append(lines, "No indicators retained.")
	}
	lines = append(lines, "Recommended safety actions")
	if len(scan.Recommendations) == 0 {
		lines = append(lines, "No recommendations retained.")
	}
	lines = append(lines, scan.Recommendations...)
	lines = append(lines, "Analysis limitations", "Risk assessments are advisory and are not proof of safety or fraud. Detection may miss threats or flag legitimate activity. Original submitted content is not retained. Unsupported font characters appear as [?].", "Generated (UTC): "+generated.UTC().Format(time.RFC3339))
	size := 0
	for _, line := range lines {
		size += len(line)
	}
	if size > 32000 {
		return nil, ErrLimit
	}
	pdf := gopdf.GoPdf{}
	pdf.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4})
	pdf.AddPage()
	if err := pdf.AddTTFFontData("Noto", font); err != nil {
		return nil, err
	}
	if err := pdf.SetFont("Noto", "", 11); err != nil {
		return nil, err
	}
	y := 45.0
	pages := 1
	for index, line := range lines {
		fontSize := 11
		heading := strings.HasPrefix(line, "Rule-based findings |") || oneOfHeading(line)
		if heading {
			fontSize = 14
		}
		if index == 0 {
			fontSize = 20
		}
		if err := pdf.SetFont("Noto", "", fontSize); err != nil {
			return nil, err
		}
		pdf.SetTextColor(35, 49, 69)
		if heading || index == 0 {
			pdf.SetTextColor(17, 55, 102)
		}
		if heading && y > 740 {
			pages++
			if pages > 12 {
				return nil, ErrLimit
			}
			pdf.AddPage()
			y = 45
		}
		lineHeight := float64(fontSize + 5)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var safe strings.Builder
		for _, r := range line {
			if unicode.IsControl(r) {
				safe.WriteByte(' ')
				continue
			}
			ok, err := pdf.IsCurrFontContainGlyph(r)
			if err != nil {
				return nil, err
			}
			if !ok {
				safe.WriteString("[?]")
			} else {
				safe.WriteRune(r)
			}
		}
		// Wrap by measured font width, including long unbroken stored strings.
		current := ""
		flush := func() error {
			if y > 785 {
				pages++
				if pages > 12 {
					return ErrLimit
				}
				pdf.AddPage()
				y = 45
			}
			pdf.SetXY(45, y)
			if err := pdf.Cell(nil, current); err != nil {
				return err
			}
			y += lineHeight
			current = ""
			return nil
		}
		for _, r := range safe.String() {
			candidate := current + string(r)
			w, err := pdf.MeasureTextWidth(candidate)
			if err != nil {
				return nil, err
			}
			if w > 500 && current != "" {
				if err = flush(); err != nil {
					return nil, err
				}
			}
			current += string(r)
		}
		if err := flush(); err != nil {
			return nil, err
		}
		y += 5
	}
	for page := 1; page <= pages; page++ {
		if err := pdf.SetPage(page); err != nil {
			return nil, err
		}
		if err := pdf.SetFont("Noto", "", 9); err != nil {
			return nil, err
		}
		pdf.SetTextColor(90, 103, 120)
		pdf.SetXY(45, 815)
		if err := pdf.Cell(nil, fmt.Sprintf("ScamGuard AI | Advisory assessment | Page %d of %d", page, pages)); err != nil {
			return nil, err
		}
	}
	data, err := pdf.GetBytesPdfReturnErr()
	if len(data) > 2<<20 {
		return nil, ErrLimit
	}
	return data, err
}

func oneOfHeading(s string) bool {
	switch s {
	case "AI analysis summary", "Triggered risk indicators", "Recommended safety actions", "Analysis limitations":
		return true
	}
	return false
}
