package report

import "github.com/buraksekili/hgraph/pkg/resolver"

// DataProvider defines the interface for accessing dependency resolution data
type DataProvider interface {
	// GetDependencies returns all resolved dependencies
	GetDependencies() []resolver.ResolvedDependency

	// GetImageToChartMapping returns mapping of image names to chart sources
	GetImageToChartMapping() map[string]string

	// GetSkippedDependencies returns dependencies that were skipped during resolution
	GetSkippedDependencies() []resolver.ResolvedDependency

	// GetAllImages returns all discovered container images
	GetAllImages() map[string]struct{}
}

// OutputFormat represents supported output formats
type OutputFormat string

const (
	FormatJSON OutputFormat = "json"
	FormatText OutputFormat = "text"
)
