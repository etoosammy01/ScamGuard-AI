package services

import (
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/detection"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/models"
)

type Detection struct{}

func (Detection) Message(content string) models.ScanResult  { return detection.AnalyzeMessage(content) }
func (Detection) URL(raw string) (models.ScanResult, error) { return detection.AnalyzeURL(raw) }
