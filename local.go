package main

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

func absPath(path, baseDir string) string {
	baseDir = filepath.FromSlash(baseDir)
	path = filepath.FromSlash(path)
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return path
}

type loadChartReq struct {
	baseDir   string
	chartName string
	repo      string
}

func (l *loadChartReq) validate() error {
	if l.baseDir == "" {
		return errors.New("baseDir is required")
	}
	if l.chartName == "" {
		return errors.New("chartName is required")
	}
	return nil
}

func lookDependenciesInCharts(currChartPath string, req *loadChartReq) (*chart.Chart, string, error) {
	chartsDirPath := absPath("charts/", currChartPath)
	_, err := os.Stat(chartsDirPath)
	if err != nil {
		return nil, "", errSkipLocalDeps
	}

	// look req.chartName in the charts/ directory of my current chart.

	depChartPath := absPath(req.chartName, chartsDirPath)
	_, err = os.Stat(depChartPath)
	if err != nil {
		return nil, "", errSkipLocalDeps
	}

	c, err := loader.Load(depChartPath)
	if err != nil {
		return nil, "", err
	}

	return c, depChartPath, nil
}
