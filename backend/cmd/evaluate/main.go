package main

import (
	"encoding/json"
	"fmt"
	"github.com/etoosammy01/ScamGuard-AI/backend/internal/evaluation"
	"os"
)

func main() {
	m, err := evaluation.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Evaluation failed:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(m) != nil {
		os.Exit(1)
	}
}
