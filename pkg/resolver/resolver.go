package resolver

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/downloader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type Resolver struct {
	// TODO; embed this to output; so not make it embedded struct.
	AllImages       map[string]struct{}
	settings        *cli.EnvSettings
	repoURLToName   map[string]string
	chartDownloader *downloader.ChartDownloader
	logger          *zap.SugaredLogger
	// visited tracks processed charts to prevent cycles and redundant work.
	// The key is in the format: "<repository_url>/<chart_name>:<chart_version>"
	visited      map[string]bool
	dependencies []ResolvedDependency
	knownRepos   map[string]bool
	imageToChart map[string]string
	skippedDeps  []ResolvedDependency

	tmpDirPath string
}

func createConsoleLogger() *zap.SugaredLogger {
	config := zapcore.EncoderConfig{
		TimeKey:       "",
		LevelKey:      "level",
		MessageKey:    "msg",
		CallerKey:     "",
		StacktraceKey: "",
		LineEnding:    zapcore.DefaultLineEnding,

		EncodeLevel: func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
			switch level {
			case zapcore.InfoLevel:
				enc.AppendString("ℹ️ ")
			case zapcore.WarnLevel:
				enc.AppendString("⚠️ ")
			case zapcore.ErrorLevel:
				enc.AppendString("❌ ")
			case zapcore.DebugLevel:
				enc.AppendString("🔍 ")
			}
		},

		EncodeName:     zapcore.FullNameEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(os.Stderr),
		zapcore.InfoLevel,
	)

	return zap.New(core).Sugar()
}

func createMinimalProgressLogger() *zap.SugaredLogger {
	config := zapcore.EncoderConfig{
		TimeKey:       "",
		LevelKey:      "",
		MessageKey:    "msg",
		CallerKey:     "",
		StacktraceKey: "",
		LineEnding:    zapcore.DefaultLineEnding,
		EncodeLevel: func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		},
		EncodeName:     zapcore.FullNameEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(os.Stderr),
		zapcore.InfoLevel,
	)

	return zap.New(core).Sugar()
}

func NewResolver(format string) *Resolver {
	settings := cli.New()

	chartDownloader := downloader.ChartDownloader{
		Out:              os.Stderr,
		Verify:           downloader.VerifyNever,
		Getters:          getter.All(settings),
		RepositoryConfig: settings.RepositoryConfig,
		RepositoryCache:  settings.RepositoryCache,
	}

	return &Resolver{
		settings:        settings,
		chartDownloader: &chartDownloader,
		repoURLToName:   make(map[string]string),
		logger:          initLogger(format),
		knownRepos:      make(map[string]bool),
		visited:         make(map[string]bool),
		dependencies:    make([]ResolvedDependency, 0),
		AllImages:       make(map[string]struct{}),
		imageToChart:    make(map[string]string),
		skippedDeps:     make([]ResolvedDependency, 0),
	}
}

type ResolvedDependency struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
	node       *ChartCtx
	parentNode *ChartCtx
}

func (d ResolvedDependency) String() string {
	return fmt.Sprintf("-\tName: %s\n\tVersion: %s\n\tRepository: %s", d.Name, d.Version, d.Repository)
}

type ChartCtx struct {
	Chart     *chart.Chart
	ChartPath string
}

type ChartResolveReq struct {
	repositoryURL string
	chartName     string
	version       string
	downloadPath  string
	parentNode    *ChartCtx
}

func (e *ChartResolveReq) Validate() error {
	if e == nil {
		return fmt.Errorf("ChartResolveReq cannot be nil")
	}

	if e.repositoryURL == "" && e.chartName == "" {
		return fmt.Errorf("both chart and repository URL cannot be empty at the same time")
	}

	return nil
}

var (
	ErrEmptyRepoURL  = errors.New("empty repo URL")
	ErrSkipLocalDeps = fmt.Errorf("skip local dependencies")
)

// ensureRepo automatically adds and updates a repository only if it's not already configured.
// TODO: this might not be safe in concurrent scenarios.
//   - collision detection: check for existing repository names before adding
//   - atomic operations: use file locking or ensure single-threaded repository modifications
//   - repository validation: verify repository accessibility before adding
func (r *Resolver) ensureRepo(repositoryURL string) (string, error) {
	if repositoryURL == "" {
		return "", ErrEmptyRepoURL
	}
	if strings.HasPrefix(repositoryURL, "file://") {
		return repositoryURL, nil
	}

	// OCI registries don't need repository setup like HTTP repos
	if registry.IsOCI(repositoryURL) {
		return repositoryURL, nil
	}

	if r.knownRepos[repositoryURL] {
		return r.repoURLToName[repositoryURL], nil
	}

	repoFile, err := repo.LoadFile(r.settings.RepositoryConfig)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("could not load repositories file: %w", err)
	}
	if repoFile == nil {
		repoFile = repo.NewFile()
	}

	var entry *repo.Entry
	for _, re := range repoFile.Repositories {
		if re.URL == repositoryURL {
			entry = re
			break
		}
	}

	if entry == nil {
		r.logger.Infof("Adding repository: %s", repositoryURL)
		parsedURL, err := url.Parse(repositoryURL)
		if err != nil {
			return "", fmt.Errorf("invalid repository URL: %s", repositoryURL)
		}

		repoName := strings.Split(parsedURL.Host, ".")[0] + "-" + strings.ReplaceAll(parsedURL.Path, "/", "-")
		repoName = strings.Trim(repoName, "-")

		entry = &repo.Entry{Name: repoName, URL: repositoryURL}
		repoFile.Add(entry)

		if err := repoFile.WriteFile(r.settings.RepositoryConfig, 0644); err != nil {
			return "", fmt.Errorf("could not write repositories file: %w", err)
		}
	}

	chartRepo, err := repo.NewChartRepository(entry, getter.All(r.settings))
	if err != nil {
		return "", fmt.Errorf("could not create repo for %s: %w", entry.Name, err)
	}
	if _, err := chartRepo.DownloadIndexFile(); err != nil { // todo: use manager here to update the repo
		return "", fmt.Errorf("failed to update the repo: %w", err)
	}

	r.knownRepos[repositoryURL] = true
	r.repoURLToName[repositoryURL] = entry.Name

	return entry.Name, nil
}

func (r *Resolver) resolveChart(req *ChartResolveReq) (*ResolvedDependency, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	tmpChartsDir := req.downloadPath

	pull := action.NewPull()
	pull.Untar = true
	pull.UntarDir = tmpChartsDir
	pull.Settings = cli.New()

	var (
		regClient *registry.Client
		chartURL  string
		username  string
		password  string
	)

	repoFile, err := repo.LoadFile(pull.Settings.RepositoryConfig)
	if err != nil {
		return nil, err
	}

	switch {
	case registry.IsOCI(req.repositoryURL):
		clientOpts := []registry.ClientOption{
			registry.ClientOptEnableCache(true),
		}

		if pull.Settings.RegistryConfig != "" {
			clientOpts = append(clientOpts, registry.ClientOptCredentialsFile(pull.Settings.RegistryConfig))
		}

		regClient, err = registry.NewClient(clientOpts...)
		if err != nil {
			return nil, fmt.Errorf("unable to create the new registry client: %w", err)
		}

		chartURL = strings.TrimSuffix(req.repositoryURL, "/") + "/" + req.chartName
		pull.Version = req.version
	case strings.HasPrefix(req.repositoryURL, "file://") || req.repositoryURL == "":
		resolvedChart := &ResolvedDependency{
			Name:       req.chartName,
			Version:    req.version,
			Repository: req.repositoryURL,
		}

		parent := req.parentNode
		parentChartPath := ""
		if parent == nil {
			// we are root
			chartPath, err := ensureAbsPath(req.chartName)
			if err != nil {
				return resolvedChart, errors.Wrap(ErrSkipLocalDeps, err.Error())
			}

			chartRequested, err := loader.Load(chartPath) // chartRequested.metadata.version
			if err != nil {
				return resolvedChart, errors.Wrap(ErrSkipLocalDeps, err.Error())
			}

			parent = &ChartCtx{
				Chart: chartRequested,
			}
			parentChartPath = chartPath
		} else {
			parentChartPath = parent.ChartPath
		}

		loadedChart, chartPath, err := findDependencyInLocalCharts(parentChartPath, req.chartName)
		if err != nil {
			return resolvedChart, errors.Wrap(ErrSkipLocalDeps, err.Error())
		}

		resolvedChart.node = &ChartCtx{
			Chart:     loadedChart,
			ChartPath: chartPath,
		}

		// Add to dependencies list if this is not the root chart
		if req.parentNode != nil {
			r.dependencies = append(r.dependencies, *resolvedChart)
		}

		return resolvedChart, nil
	default:
		if repoFile != nil {
			for _, repo := range repoFile.Repositories {
				if repo.URL == req.repositoryURL {
					username = repo.Username
					password = repo.Password
				}
			}
		}

		chartURL, err = repo.FindChartInAuthAndTLSRepoURL(
			req.repositoryURL,
			username,
			password,
			req.chartName,
			req.version,
			pull.CertFile,
			pull.KeyFile,
			pull.CaFile,
			true,
			getter.All(pull.Settings),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to pull the helm chart: %w", err)
		}
	}

	chartDownloader := downloader.ChartDownloader{
		Out:              io.Discard,
		RegistryClient:   regClient,
		RepositoryConfig: pull.Settings.RepositoryConfig,
		RepositoryCache:  pull.Settings.RepositoryCache,
		Verify:           downloader.VerifyNever,
		Getters:          getter.All(pull.Settings),
		Options: []getter.Option{
			getter.WithInsecureSkipVerifyTLS(true),
			getter.WithBasicAuth(username, password),
		},
	}

	saved, _, err := chartDownloader.DownloadTo(chartURL, pull.Version, tmpChartsDir)
	if err != nil {
		return nil, fmt.Errorf("unable to download the helm chart: %w", err)
	}

	chart, err := loader.Load(saved)
	if err != nil {
		return nil, fmt.Errorf("could not load chart from %s: %w", saved, err)
	}

	// for remote charts, we need to use the extracted directory path for dependency resolution,
	// not the .tgz file path. The chart gets extracted to a directory with the chart name.
	// From the debug output, we can see it's extracted to the working directory, not tmpChartsDir.
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}
	extractedDir := filepath.Join(wd, chart.Name())

	dep := ResolvedDependency{
		Name:       chart.Name(),
		Version:    chart.Metadata.Version,
		Repository: req.repositoryURL,
		node: &ChartCtx{
			Chart:     chart,
			ChartPath: extractedDir,
		},
	}

	r.dependencies = append(r.dependencies, dep)

	return &dep, nil
}

func (r *Resolver) extractImagesFromChart(dep *ResolvedDependency) error {
	if dep.node.Chart == nil {
		return nil
	}

	actionConfig := new(action.Configuration)
	settings := r.settings

	// TODO: look for better way to initialize this
	err := actionConfig.Init(
		settings.RESTClientGetter(),
		settings.Namespace(),
		os.Getenv("HELM_DRIVER"),
		func(format string, v ...interface{}) {},
	)
	if err != nil {
		return err
	}

	templateAction := action.NewInstall(actionConfig)
	templateAction.DryRun = true
	templateAction.ReleaseName = "hgraph"
	templateAction.Namespace = "default"

	release, err := templateAction.Run(dep.node.Chart, nil)
	if err != nil {
		return err
	}

	imagesInChart := parseManifestFile(release.Manifest)
	for img := range imagesInChart {
		r.AllImages[img] = struct{}{}
		r.imageToChart[img] = dep.Name
	}

	return nil
}

// resolveRecursive performs the actual recursive dependency resolution.
func (r *Resolver) resolveRecursive(chartName, version, repositoryURL string, parentNode *ChartCtx) error {
	_, err := r.ensureRepo(repositoryURL)
	if err != nil {
		if !errors.Is(err, ErrEmptyRepoURL) {
			return err
		}
	}

	uniqueID := fmt.Sprintf("%s/%s:%s", repositoryURL, chartName, version)
	if r.visited[uniqueID] {
		return nil
	}

	r.visited[uniqueID] = true

	dep, err := r.resolveChart(&ChartResolveReq{
		repositoryURL: repositoryURL,
		chartName:     chartName,
		version:       version,
		downloadPath:  r.tmpDirPath,
		parentNode:    parentNode,
	})
	if err != nil {
		if errors.Is(err, ErrSkipLocalDeps) {
			r.skippedDeps = append(r.skippedDeps, *dep)
			return nil
		}

		return err
	}

	if dep.node.Chart == nil {
		return nil
	}

	err = r.extractImagesFromChart(dep)
	if err != nil {
		return err
	}

	deps := dep.node.Chart.Metadata.Dependencies
	newParentNode := ChartCtx{
		Chart:     dep.node.Chart,
		ChartPath: dep.node.ChartPath,
	}

	for _, subDep := range deps {
		err := r.resolveRecursive(subDep.Name, subDep.Version, subDep.Repository, &newParentNode)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Resolver) SetQuietMode(quiet bool) {
	if quiet {
		r.logger = zap.NewNop().Sugar()
	} else {
		r.logger = createConsoleLogger()
	}
}

// Resolve is the public entry point for starting the dependency resolution process.
func (r *Resolver) Resolve(chartName, version, repositoryURL string) ([]ResolvedDependency, error) {
	r.visited = make(map[string]bool)
	r.dependencies = make([]ResolvedDependency, 0)
	r.imageToChart = make(map[string]string)

	r.logger.Infof("Resolving chart dependencies...")

	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	tmpChartsDir, err := os.MkdirTemp(wd, "charts-*")
	if err != nil {
		return nil, err
	}

	r.tmpDirPath = tmpChartsDir

	defer func() {
		err = os.RemoveAll(tmpChartsDir)
		if err != nil {
			r.logger.Warn("Failed to remove temporary charts directory")
		}
	}()

	if repositoryURL == "" {
		if registry.IsOCI(chartName) {
			// extract repository and chart from OCI URL
			// oci://registry-1.docker.io/bitnamicharts/airflow ->
			// repo: oci://registry-1.docker.io/bitnamicharts, chart: airflow
			repoURL, extractedChartName, err := parseOCIChartURL(chartName)
			if err != nil {
				return nil, fmt.Errorf("invalid OCI chart URL: %w", err)
			}
			repositoryURL = repoURL
			chartName = extractedChartName
		} else {
			chartName, err = ensureAbsPath(chartName)
			if err != nil {
				return nil, err
			}
		}
	}

	err = r.resolveRecursive(chartName, version, repositoryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	r.logger.Infof("Completed. Found %d dependencies.", len(r.dependencies))

	return r.dependencies, nil
}

func ensureAbsPath(p string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}

	return filepath.Abs(p)
}

func parseOCIChartURL(ociURL string) (repoURL, chartName string, err error) {
	// oci://registry-1.docker.io/bitnamicharts/airflow
	// -> repoURL: oci://registry-1.docker.io/bitnamicharts
	// -> chartName: airflow

	if !registry.IsOCI(ociURL) {
		return "", "", fmt.Errorf("not an OCI URL: %s", ociURL)
	}

	parts := strings.Split(ociURL, "/")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid OCI URL format: %s", ociURL)
	}

	chartName = parts[len(parts)-1]
	repoURL = strings.Join(parts[:len(parts)-1], "/")
	return repoURL, chartName, nil
}

func parseManifestFile(content string) map[string]struct{} {
	const imageQuery = "$..image"

	uniqueImages := make(map[string]struct{})

	documents := strings.Split(content, "---")
	for _, doc := range documents {
		if strings.TrimSpace(doc) == "" {
			continue
		}

		var data interface{}
		if err := yaml.Unmarshal([]byte(doc), &data); err != nil {
			continue
		}

		var validData interface{}
		if slice, ok := data.([]interface{}); ok {
			validData = slice
		} else if mapData, ok := data.(map[string]interface{}); ok {
			validData = mapData
		} else {
			continue
		}

		// check if kind is Deployment or Pod or Job or StatefulSet or DaemonSet
		result, err := jsonpath.Get("$.kind", validData)
		if err != nil {
			continue
		}

		if kind, ok := result.(string); !ok || (kind != "Deployment" && kind != "Pod" && kind != "Job" && kind != "StatefulSet" && kind != "DaemonSet") {
			continue
		}

		result, err = jsonpath.Get(imageQuery, validData)
		if err != nil {
			continue
		}

		if resultsSlice, ok := result.([]interface{}); ok {
			for _, item := range resultsSlice {
				if imageStr, ok := item.(string); ok {
					uniqueImages[imageStr] = struct{}{}
				}
			}
		}
	}

	return uniqueImages
}

// findDependencyInLocalCharts looks for chart (specified in req.chartName) in the given chart's (which is located in currChartPath) `charts/` directory.
// It handles both directory format (remote charts) and .tgz format (local charts built with helm dep build).
func findDependencyInLocalCharts(parentChartPath, chartName string) (*chart.Chart, string, error) {
	// first, check if charts/ directory exists in the chart.
	chartsDir := absPath("charts/", parentChartPath)
	if _, err := os.Stat(chartsDir); err != nil {
		return nil, "", ErrSkipLocalDeps
	}

	// try to find as a directory (remote chart format)
	// Example: <actual_chart>/charts/<dependency_chart>/
	depChartDirPath := absPath(chartName, chartsDir)
	if _, err := os.Stat(depChartDirPath); err == nil {
		c, err := loader.Load(depChartDirPath)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to load chart directory %s", depChartDirPath)
		}

		return c, depChartDirPath, nil
	}

	// try to find as .tgz file (local chart format)
	// Example: <actual_chart>/charts/<dependency_chart>-<dependency_chart_version>.tgz
	tgzFilepath := filepath.Join(chartsDir, chartName+"-*.tgz")
	matches, err := filepath.Glob(tgzFilepath)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to glob pattern %s", tgzFilepath)
	}

	if len(matches) == 0 {
		return nil, "", errors.Wrapf(
			ErrSkipLocalDeps,
			"chart %s not found in %s (tried directory and .tgz formats)",
			chartName,
			chartsDir,
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
	sourceDirPath := filepath.Join(filepath.Dir(filepath.Dir(chartsDir)), chartName)

	// return the dependency chart with source directory path
	return c, sourceDirPath, nil
}

func absPath(path, baseDir string) string {
	baseDir = filepath.FromSlash(baseDir)
	path = filepath.FromSlash(path)
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return path
}

func initLogger(format string) *zap.SugaredLogger {
	if format == "text" {
		return createConsoleLogger()
	}

	if format == "json" {
		return createMinimalProgressLogger()
	}

	return zap.NewNop().Sugar()
}

// GetDependencies implements report.DataProvider
func (r *Resolver) GetDependencies() []ResolvedDependency {
	return r.dependencies
}

// GetImageToChartMapping implements report.DataProvider
func (r *Resolver) GetImageToChartMapping() map[string]string {
	return r.imageToChart
}

// GetSkippedDependencies implements report.DataProvider
func (r *Resolver) GetSkippedDependencies() []ResolvedDependency {
	return r.skippedDeps
}

// GetAllImages implements report.DataProvider
func (r *Resolver) GetAllImages() map[string]struct{} {
	return r.AllImages
}
