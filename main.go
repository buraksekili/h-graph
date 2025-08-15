package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
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
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
	IsLocal    bool   `json:"isLocal"`

	chart *chart.Chart `json:"-"`
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

	defer func() {
		err = os.RemoveAll(tmpChartsDir)
		if err != nil {
			r.logln("Failed to remove temporary charts directory")
		}
	}()

	err = r.resolveRecursive(chartName, version, repositoryURL, tmpChartsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	return r.dependencies, nil
}

func unpackChart(dst, src string) error {
	err := chartutil.ExpandFile(dst, src)
	if err != nil {
		return err
	}

	return nil
}

type exploreReq struct {
	repositoryURL string
	chartName     string
	version       string
	downloadPath  string
}

func (e *exploreReq) validate() error {
	if e == nil {
		return fmt.Errorf("exploreReq cannot be nil")
	}

	if e.repositoryURL == "" {
		return fmt.Errorf("empty repositoryURL")
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
	case strings.HasPrefix(req.repositoryURL, "file://"):
		return &ResolvedDependency{
			Name:       req.chartName,
			Version:    req.version,
			Repository: req.repositoryURL,
			IsLocal:    true,
		}, errSkipLocalDeps
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
	dep := ResolvedDependency{
		Name:       chart.Name(),
		Version:    chart.Metadata.Version,
		Repository: req.repositoryURL,
		chart:      chart,
	}
	r.dependencies = append(r.dependencies, dep)

	return &dep, nil
}

func (r *Resolver) images(dep *ResolvedDependency) error {
	if dep.chart == nil {
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
	templateAction.ReleaseName = dep.Name
	templateAction.Namespace = "default"

	release, err := templateAction.Run(dep.chart, nil)
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
func (r *Resolver) resolveRecursive(chartName, version, repositoryURL, baseDir string) error {
	if repositoryURL == "" {
		return nil
	}

	repoName, err := r.ensureRepo(repositoryURL)
	if err != nil {
		return err
	}

	uniqueID := fmt.Sprintf("%s/%s:%s", repositoryURL, chartName, version)
	if r.visited[uniqueID] {
		return nil
	}

	r.visited[uniqueID] = true

	chartRef := fmt.Sprintf("%s/%s", repoName, chartName)
	dep, err := r.exploreNode(&exploreReq{
		repositoryURL: repositoryURL,
		chartName:     chartName,
		version:       version,
		downloadPath:  baseDir,
	})
	if err != nil {
		if errors.Is(err, errSkipLocalDeps) {
			r.skippedDeps = append(r.skippedDeps, *dep)
			return nil
		}

		return fmt.Errorf("could not download chart %s:%s from %s: %w", chartRef, version, repositoryURL, err)
	}

	if dep.chart == nil {
		return nil
	}

	err = r.images(dep)
	if err != nil {
		return err
	}

	deps := dep.chart.Metadata.Dependencies

	for _, subDep := range deps {
		err := r.resolveRecursive(subDep.Name, subDep.Version, subDep.Repository, baseDir)
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

// ensureRepo automatically adds and updates a repository only if it's not already configured.
func (r *Resolver) ensureRepo(repositoryURL string) (string, error) {
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
		chartName, _ := cmd.Flags().GetString("name")
		repoName, _ := cmd.Flags().GetString("repo-name")
		repoURL, _ := cmd.Flags().GetString("repo-url")
		version, _ := cmd.Flags().GetString("version")
		format, _ := cmd.Flags().GetString("format")

		if chartName == "" {
			fmt.Println("❌ Chart name is required. Use --name flag.")
			return
		}
		if repoName == "" {
			fmt.Println("❌ Repository name is required. Use --repo-name flag.")
			return
		}
		if repoURL == "" {
			fmt.Println("❌ Repository URL is required. Use --repo-url flag.")
			return
		}
		if version == "" {
			fmt.Println("❌ Chart version is required. Use --version flag.")
			return
		}

		// Validate format
		if format != "text" && format != "json" {
			fmt.Printf("❌ Invalid format '%s'. Supported formats: text, json\n", format)
			return
		}

		resolver := NewResolver()

		// Set quiet mode for JSON format to avoid polluting stdout
		if format == "json" {
			resolver.SetQuietMode(true)
		} else {
			fmt.Printf("🔍 Resolving dependencies for chart: %s\n", chartName)
			fmt.Printf("📦 Repository: %s (%s)\n", repoName, repoURL)
		}

		resolved, err := resolver.Resolve(chartName, version, repoURL)
		if err != nil {
			log.Fatalf("❌ Resolution failed: %v", err)
		}

		switch format {
		case "json":
			report := resolver.GenerateReport(chartName, version, repoURL)
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
	depsCmd.Flags().StringP("name", "n", "", "Chart name (required)")
	depsCmd.Flags().StringP("repo-name", "r", "", "Repository name (required)")
	depsCmd.Flags().StringP("repo-url", "u", "", "Repository URL (required)")
	depsCmd.Flags().StringP("version", "v", "", "Chart version (required)")
	depsCmd.Flags().StringP("format", "f", "text", "Output format (text, json)")

	depsCmd.MarkFlagRequired("name")
	depsCmd.MarkFlagRequired("repo-name")
	depsCmd.MarkFlagRequired("repo-url")
	depsCmd.MarkFlagRequired("version")
}

func main() {
	rootCmd.AddCommand(depsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
