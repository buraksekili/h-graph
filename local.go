package main

import (
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"os"
	"path/filepath"
)

func absPath(path, baseDir string) string {
	baseDir = filepath.FromSlash(baseDir)
	path = filepath.FromSlash(path)
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return path
}

type findDepInChartsReq struct {
	baseDir   string
	chartName string
	repo      string
}

func (l *findDepInChartsReq) validate() error {
	if l.baseDir == "" {
		return errors.New("baseDir is required")
	}
	if l.chartName == "" {
		return errors.New("chartName is required")
	}
	return nil
}

// findDepInChartsDir looks for chart (specified in req.chartName) in the given chart's (which is located in currChartPath) `charts/` directory.
// It handles both directory format (remote charts) and .tgz format (local charts built with helm dep build).
func findDepInChartsDir(currChartPath string, req *findDepInChartsReq) (*chart.Chart, string, error) {
	// first, check if charts/ directory exists in the chart.
	chartsDirPath := absPath("charts/", currChartPath)
	if _, err := os.Stat(chartsDirPath); err != nil {
		return nil, "", errSkipLocalDeps
	}

	// try to find as a directory (remote chart format)
	// Example: <actual_chart>/charts/<dependency_chart>/
	depChartDirPath := absPath(req.chartName, chartsDirPath)
	if _, err := os.Stat(depChartDirPath); err == nil {
		c, err := loader.Load(depChartDirPath)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to load chart directory %s", depChartDirPath)
		}

		return c, depChartDirPath, nil
	}

	// try to find as .tgz file (local chart format)
	// Example: <actual_chart>/charts/<dependency_chart>-<dependency_chart_version>.tgz
	pattern := filepath.Join(chartsDirPath, req.chartName+"-*.tgz")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to glob pattern %s", pattern)
	}

	if len(matches) == 0 {
		return nil, "", errors.Wrapf(
			errSkipLocalDeps,
			"chart %s not found in %s (tried directory and .tgz formats)",
			req.chartName,
			chartsDirPath,
		)
	}

	// TODO: for now, use the first match (or we could implement version selection logic here)
	//		If multiple .tgz files exist, try to pick the best one.
	//		For now, just use the first one but this could be enhanced,
	//		to parse versions and pick the latest or match a specific version
	depChartTgzPath := matches[0]
	if len(matches) > 1 {
	}

	// try to load the dependency chart (.tgz file)
	c, err := loader.Load(depChartTgzPath)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to load chart archive %s", depChartTgzPath)
	}

	// for .tgz files, we need to return the source directory path instead of the .tgz path
	// This is crucial for subsequent dependency resolution to work correctly
	// The source directory is typically: charts/<chartname>/
	sourceDirPath := filepath.Join(filepath.Dir(filepath.Dir(chartsDirPath)), req.chartName)

	// return the dependency chart with source directory path
	return c, sourceDirPath, nil
}
