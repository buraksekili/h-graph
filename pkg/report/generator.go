package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/buraksekili/h-graph/pkg/resolver"
)

// Generator handles report creation and formatting
type Generator struct {
	provider DataProvider
}

// NewGenerator creates a new report generator with the given data provider
func NewGenerator(provider DataProvider) *Generator {
	return &Generator{
		provider: provider,
	}
}

func (g *Generator) Generate(chartName, version, repositoryURL string) *Report {
	dependencies := g.provider.GetDependencies()
	imageMapping := g.provider.GetImageToChartMapping()
	allImages := g.provider.GetAllImages()
	skippedCharts := g.provider.GetSkippedDependencies()

	images := make([]ImageInfo, 0, len(allImages))
	for img := range allImages {
		source := imageMapping[img]
		if source == "" {
			source = chartName
		}
		images = append(images, ImageInfo{
			Name:   img,
			Source: source,
		})
	}

	return &Report{
		Chart: ChartInfo{
			Name:       chartName,
			Version:    version,
			Repository: repositoryURL,
		},
		Dependencies: dependencies,
		Images:       images,
		Summary: Summary{
			TotalDependencies: len(dependencies),
			TotalImages:       len(images),
			GeneratedAt:       time.Now(),
		},
		SkippedCharts: skippedCharts,
	}
}

func (g *Generator) GenerateError(chartName, version, repositoryURL, errorMsg string) *Report {
	return &Report{
		Chart: ChartInfo{
			Name:       chartName,
			Version:    version,
			Repository: repositoryURL,
		},
		Dependencies: []resolver.ResolvedDependency{},
		Images:       []ImageInfo{},
		Summary: Summary{
			TotalDependencies: 0,
			TotalImages:       0,
			GeneratedAt:       time.Now(),
		},
		SkippedCharts: []resolver.ResolvedDependency{},
		Error:         errorMsg,
	}
}

func (g *Generator) OutputJSON(report *Report) error {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}
