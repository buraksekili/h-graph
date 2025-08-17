package report

import (
	"time"

	"github.com/buraksekili/h-graph/pkg/resolver"
)

// ImageInfo represents container image information in a report
type ImageInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// ChartInfo represents the main chart being analyzed
type ChartInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
}

// Summary contains aggregate statistics about the dependency resolution
type Summary struct {
	TotalDependencies int       `json:"total_dependencies"`
	TotalImages       int       `json:"total_images"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// Report represents a complete dependency analysis report
type Report struct {
	Chart         ChartInfo                     `json:"chart"`
	Dependencies  []resolver.ResolvedDependency `json:"dependencies"`
	Images        []ImageInfo                   `json:"images"`
	Summary       Summary                       `json:"summary"`
	SkippedCharts []resolver.ResolvedDependency `json:"skipped_charts"`
}
