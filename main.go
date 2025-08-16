package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/registry"

	"github.com/PaesslerAG/jsonpath"
	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/downloader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type ResolvedDependency struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Repository  string       `json:"repository"`
	currentNode *currentNode `json:"-"`
	parentDep   *parentDep   `json:"-"`
}

type currentNode struct {
	chart *chart.Chart
	saved string
}

type parentDep struct {
	chart *chart.Chart
	saved string
}

func (d ResolvedDependency) String() string {
	return fmt.Sprintf("-\tName: %s\n\tVersion: %s\n\tRepository: %s", d.Name, d.Version, d.Repository)
}

type ImageInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type DependencyReport struct {
	Chart struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Repository string `json:"repository"`
	} `json:"chart"`
	Dependencies []ResolvedDependency `json:"dependencies"`
	Images       []ImageInfo          `json:"images"`
	Summary      struct {
		TotalDependencies int       `json:"total_dependencies"`
		TotalImages       int       `json:"total_images"`
		GeneratedAt       time.Time `json:"generated_at"`
	} `json:"summary"`

	SkippedCharts []ResolvedDependency `json:"skipped_charts"`
}

type Resolver struct {
	settings        *cli.EnvSettings
	repoURLToName   map[string]string
	chartDownloader *downloader.ChartDownloader
	out             *os.File
	// visited tracks processed charts to prevent cycles and redundant work.
	// The key is in the format: "<repository_url>/<chart_name>:<chart_version>"
	visited      map[string]bool
	dependencies []ResolvedDependency
	knownRepos   map[string]bool
	allImages    map[string]struct{}
	imageToChart map[string]string
	skippedDeps  []ResolvedDependency

	tmpDirPath string
}

func NewResolver() *Resolver {
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
		out:             os.Stderr,
		knownRepos:      make(map[string]bool),
		visited:         make(map[string]bool),
		dependencies:    make([]ResolvedDependency, 0),
		allImages:       make(map[string]struct{}),
		imageToChart:    make(map[string]string),
		skippedDeps:     make([]ResolvedDependency, 0),
	}
}

// logf prints formatted output to the resolver's output stream (if enabled)
func (r *Resolver) logf(format string, args ...interface{}) {
	if r.out != nil {
		fmt.Fprintf(r.out, format, args...)
	}
}

// logln prints a line to the resolver's output stream (if enabled)
func (r *Resolver) logln(args ...interface{}) {
	if r.out != nil {
		fmt.Fprintln(r.out, args...)
	}
}

func (r *Resolver) SetQuietMode(quiet bool) {
	if quiet {
		r.out = nil
	} else {
		r.out = os.Stderr
	}
}

// Resolve is the public entry point for starting the dependency resolution process.
func (r *Resolver) Resolve(chartName, version, repositoryURL string) ([]ResolvedDependency, error) {
	r.visited = make(map[string]bool)
	r.dependencies = make([]ResolvedDependency, 0)
	r.imageToChart = make(map[string]string)

	r.logf("Starting dependency resolution for chart: %s\n", chartName)

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
			r.logln("Failed to remove temporary charts directory")
		}
	}()

	if repositoryURL == "" {
		chartName, err = ensureAbsPath(chartName)
		if err != nil {
			return nil, err
		}
	}

	err = r.resolveRecursive(chartName, version, repositoryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	return r.dependencies, nil
}

// GetLocalPath generates absolute local path when use
// "file://" in repository of dependencies
func GetLocalPath(repo, chartPath string) (string, error) {
	var depPath string
	var err error
	p := strings.TrimPrefix(repo, "file://")

	// root path is absolute
	if strings.HasPrefix(p, "/") {
		if depPath, err = filepath.Abs(p); err != nil {
			return "", err
		}
	} else {
		depPath = filepath.Join(chartPath, p)
	}

	if _, err = os.Stat(depPath); errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("directory %s not found", depPath)
	} else if err != nil {
		return "", err
	}

	return depPath, nil
}

type exploreReq struct {
	repositoryURL string
	chartName     string
	version       string
	downloadPath  string
	parentNode    *parentDep
}

func (e *exploreReq) validate() error {
	if e == nil {
		return fmt.Errorf("exploreReq cannot be nil")
	}

	if e.repositoryURL == "" && e.chartName == "" {
		return fmt.Errorf("both chart and repository URL cannot be empty at the same time")
	}

	return nil
}

var errSkipLocalDeps = fmt.Errorf("skip local dependencies")

func (r *Resolver) exploreNode(req *exploreReq) (*ResolvedDependency, error) {
	err := req.validate()
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
		regClient, err = registry.NewClient(registry.ClientOptEnableCache(true))
		if err != nil {
			return nil, fmt.Errorf("unable to create the new registry client: %w", err)
		}

		chartURL = req.repositoryURL
		pull.Version = req.version
	case strings.HasPrefix(req.repositoryURL, "file://") || req.repositoryURL == "":
		dep := &ResolvedDependency{
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
				return dep, errors.Wrap(errSkipLocalDeps, err.Error())
			}

			chartRequested, err := loader.Load(chartPath) // chartRequested.metadata.version
			if err != nil {
				return dep, errors.Wrap(errSkipLocalDeps, err.Error())
			}

			parent = &parentDep{
				chart: chartRequested,
			}
			parentChartPath = chartPath
		} else {
			parentChartPath = parent.saved
		}

		c, chartPath, err := findDepInChartsDir(parentChartPath, &findDepInChartsReq{
			baseDir:   parentChartPath,
			chartName: req.chartName,
		})
		if err != nil {
			return dep, errors.Wrap(errSkipLocalDeps, err.Error())
		}

		dep.currentNode = &currentNode{
			chart: c,
			saved: chartPath,
		}

		// Add to dependencies list if this is not the root chart
		if req.parentNode != nil {
			r.dependencies = append(r.dependencies, *dep)
		}

		return dep, nil
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
		currentNode: &currentNode{
			chart: chart,
			saved: extractedDir,
		},
	}

	r.dependencies = append(r.dependencies, dep)

	return &dep, nil
}

func (r *Resolver) images(dep *ResolvedDependency) error {
	if dep.currentNode.chart == nil {
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

	release, err := templateAction.Run(dep.currentNode.chart, nil)
	if err != nil {
		return err
	}

	imagesInChart := parseManifestFile(release.Manifest)
	for img := range imagesInChart {
		r.allImages[img] = struct{}{}
		r.imageToChart[img] = dep.Name
	}

	return nil
}

// resolveRecursive performs the actual recursive dependency resolution.
func (r *Resolver) resolveRecursive(chartName, version, repositoryURL string, parentNode *parentDep) error {
	_, err := r.ensureRepo(repositoryURL)
	if err != nil {
		if !errors.Is(err, errEmptyRepoURL) {
			return err
		}
	}

	uniqueID := fmt.Sprintf("%s/%s:%s", repositoryURL, chartName, version)
	if r.visited[uniqueID] {
		return nil
	}

	r.visited[uniqueID] = true

	dep, err := r.exploreNode(&exploreReq{
		repositoryURL: repositoryURL,
		chartName:     chartName,
		version:       version,
		downloadPath:  r.tmpDirPath,
		parentNode:    parentNode,
	})
	if err != nil {
		if errors.Is(err, errSkipLocalDeps) {
			r.skippedDeps = append(r.skippedDeps, *dep)
			return nil
		}

		return err
	}

	if dep.currentNode.chart == nil {
		return nil
	}

	err = r.images(dep)
	if err != nil {
		return err
	}

	deps := dep.currentNode.chart.Metadata.Dependencies
	newParentNode := parentDep{
		chart: dep.currentNode.chart,
		saved: dep.currentNode.saved,
	}

	for _, subDep := range deps {
		err := r.resolveRecursive(subDep.Name, subDep.Version, subDep.Repository, &newParentNode)
		if err != nil {
			return err
		}
	}

	return nil
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

func (r *Resolver) GenerateReport(chartName, version, repositoryURL string) *DependencyReport {
	report := &DependencyReport{
		Dependencies: r.dependencies,
	}

	report.Chart.Name = chartName
	report.Chart.Version = version
	report.Chart.Repository = repositoryURL

	images := make([]ImageInfo, 0, len(r.allImages))
	for img := range r.allImages {
		source := r.imageToChart[img]
		if source == "" {
			source = chartName
		}
		images = append(images, ImageInfo{
			Name:   img,
			Source: source,
		})
	}

	report.Images = images

	report.Summary.TotalDependencies = len(r.dependencies)
	report.Summary.TotalImages = len(images)
	report.Summary.GeneratedAt = time.Now()
	report.SkippedCharts = r.skippedDeps

	return report
}

// OutputJSON outputs the report in JSON format
func (r *Resolver) OutputJSON(report *DependencyReport) error {
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

var rootCmd = &cobra.Command{
	Use:   "hg",
	Short: "A tool to analyze Helm chart dependencies and images.",
	Long:  `A powerful CLI tool built with Cobra to inspect Helm charts, list their dependencies, and visualize their dependency graph.`,
}

var errEmptyRepoURL = errors.New("empty repo URL")

// ensureRepo automatically adds and updates a repository only if it's not already configured.
func (r *Resolver) ensureRepo(repositoryURL string) (string, error) {
	if repositoryURL == "" {
		return "", errEmptyRepoURL
	}
	if strings.HasPrefix(repositoryURL, "file://") {
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
		r.logf("✨ Discovered new repository. Adding and updating: %s\n", repositoryURL)
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

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Finds all chart and image dependencies for a given chart",
	Long: `Finds all chart and image dependencies for a given chart.
Use flags to specify the chart name, repository name, and repository URL.
All three flags are required for dependency resolution.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: what happens if both repo and chart defined?
		// tip: fallback to reading remote
		repoURL, _ := cmd.Flags().GetString("repo")
		chart, _ := cmd.Flags().GetString("chart")
		version, _ := cmd.Flags().GetString("version")
		format, _ := cmd.Flags().GetString("format")

		if repoURL == "" && chart == "" {
			fmt.Println("X Both Repository URL and Path empty, one of them is required.")
			return
		}

		resolver := NewResolver()

		if format == "json" {
			resolver.SetQuietMode(true)
		} else if format == "text" {
			fmt.Printf("🔍 Resolving dependencies for chart: %s\n", chart)
		} else {
			fmt.Printf("❌ Invalid format '%s'. Supported formats: text, json\n", format)
			return
		}

		resolved, err := resolver.Resolve(chart, version, repoURL)
		if err != nil {
			log.Fatalf("❌ Resolution failed: %v", err)
		}

		switch format {
		case "json":
			report := resolver.GenerateReport(chart, version, repoURL)
			if err := resolver.OutputJSON(report); err != nil {
				log.Fatalf("❌ Failed to output JSON: %v", err)
			}
		default:
			fmt.Println("✅ Dependency resolution complete. Found unique dependencies:")
			fmt.Println("--------------------------------------------------")
			for _, dep := range resolved {
				fmt.Println(dep.String())
			}
			fmt.Println("\n🐳 Container Images:")
			fmt.Println("--------------------------------------------------")
			for img := range resolver.allImages {
				fmt.Println(img)
			}
		}
	},
}

func init() {
	depsCmd.Flags().StringP("chart", "c", "", "Chart name")
	depsCmd.Flags().StringP("repo", "r", "", "Repository URL")
	depsCmd.Flags().StringP("version", "v", "", "Chart version")
	depsCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")
}

func main() {
	rootCmd.AddCommand(depsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func loadChartDir(chartPath string) (*chart.Chart, error) {
	if fi, err := os.Stat(chartPath); err != nil {
		return nil, errors.Wrapf(err, "could not find %s", chartPath)
	} else if !fi.IsDir() {
		return nil, errors.New("only unpacked charts can be updated")
	}

	return loader.LoadDir(chartPath)
}

func locateLocalDependencies(baseChartPath string) ([]string, error) {
	visited := make(map[string]bool)
	deps, err := locateDepsRecursiveHelper(baseChartPath, visited)
	if err != nil {
		return nil, err
	}

	for i, j := 0, len(deps)-1; i < j; i, j = i+1, j-1 {
		deps[i], deps[j] = deps[j], deps[i]
	}

	return deps, nil
}

// locateDepsRecursiveHelper contains the core recursive logic.
func locateDepsRecursiveHelper(chartPath string, visited map[string]bool) ([]string, error) {
	if visited[chartPath] {
		return []string{}, nil
	}

	visited[chartPath] = true

	deps := []string{}

	chart, err := loadChartDir(chartPath)
	if err != nil {
		return nil, err
	}

	for _, dependency := range chart.Metadata.Dependencies {
		if !strings.HasPrefix(dependency.Repository, "file://") {
			continue
		}

		depPath, err := filepath.Abs(
			filepath.Join(chartPath, dependency.Repository[7:]),
		)
		if err != nil {
			return nil, err
		}

		deps = append(deps, depPath)

		subDeps, err := locateDepsRecursiveHelper(depPath, visited)
		if err != nil {
			return nil, err
		}
		deps = append(deps, subDeps...)
	}

	return deps, nil
}

func ensureAbsPath(p string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}

	return filepath.Abs(p)
}
