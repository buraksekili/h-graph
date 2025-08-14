package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

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

// SetQuietMode disables progress output for JSON format
func (r *Resolver) SetQuietMode(quiet bool) {
	if quiet {
		r.out = nil // Disable output
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

// resolveRecursive performs the actual recursive dependency resolution.
func (r *Resolver) resolveRecursive(chartName, version, repositoryURL, dir string) error {
	repoName, err := r.ensureRepo(repositoryURL)
	if err != nil {
		return err
	}

	uniqueID := fmt.Sprintf("%s/%s:%s", repositoryURL, chartName, version)
	if r.visited[uniqueID] {
		r.logf("  -> Skipping already visited chart: %s\n", uniqueID)
		return nil
	}

	r.visited[uniqueID] = true
	r.logf("🔍 Resolving: %s\n", uniqueID)

	chartRef := fmt.Sprintf("%s/%s", repoName, chartName)
	saved, _, err := r.chartDownloader.DownloadTo(chartRef, version, dir)
	if err != nil {
		return fmt.Errorf("could not download chart %s:%s from %s: %w", chartRef, version, repositoryURL, err)
	}

	chart, err := loader.Load(saved)
	if err != nil {
		return fmt.Errorf("could not load chart from %s: %w", saved, err)
	}

	dep := ResolvedDependency{
		Name:       chart.Name(),
		Version:    chart.Metadata.Version,
		Repository: repositoryURL,
	}

	r.dependencies = append(r.dependencies, dep)

	actionConfig := new(action.Configuration)

	settings := r.settings
	if err := actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), os.Getenv("HELM_DRIVER"), log.Printf); err != nil {
		log.Fatalf("❌ Failed to initialize action config: %v", err)
	}
	templateAction := action.NewInstall(actionConfig)
	templateAction.DryRun = true
	templateAction.ReleaseName = dep.Name
	templateAction.Namespace = "default"

	release, err := templateAction.Run(chart, nil)
	if err != nil {
		log.Printf("WARNING: Could not template chart %s: %v", chartRef, err)
	} else {
		imagesInChart := parseManifestFile(release.Manifest)
		for img := range imagesInChart {
			r.allImages[img] = struct{}{}
			r.imageToChart[img] = dep.Name
		}
	}

	for _, dep := range chart.Metadata.Dependencies {
		if dep.Repository == "" || strings.Contains(dep.Repository, "file://") {
			continue
		}

		r.logf("  -> Found dependency: %s:%s\n", dep.Name, dep.Version)

		err := r.resolveRecursive(dep.Name, dep.Version, dep.Repository, dir)
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

// GenerateReport creates a structured dependency report
func (r *Resolver) GenerateReport(chartName, version, repositoryURL string) *DependencyReport {
	report := &DependencyReport{
		Dependencies: r.dependencies,
	}

	// Set chart information
	report.Chart.Name = chartName
	report.Chart.Version = version
	report.Chart.Repository = repositoryURL

	// Convert images map to slice with source information
	images := make([]ImageInfo, 0, len(r.allImages))
	for img := range r.allImages {
		source := r.imageToChart[img]
		if source == "" {
			source = chartName // Default to main chart if source unknown
		}
		images = append(images, ImageInfo{
			Name:   img,
			Source: source,
		})
	}
	report.Images = images

	// Set summary information
	report.Summary.TotalDependencies = len(r.dependencies)
	report.Summary.TotalImages = len(images)
	report.Summary.GeneratedAt = time.Now()

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
	if _, err := chartRepo.DownloadIndexFile(); err != nil {
		r.logf("WARNING: could not update repo %s: %v\n", entry.Name, err)
	}

	r.knownRepos[repositoryURL] = true
	r.repoURLToName[repositoryURL] = entry.Name

	return entry.Name, nil
}

func validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	_, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	return nil
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

		if err := validateURL(repoURL); err != nil {
			fmt.Printf("❌ Invalid repository URL: %v\n", err)
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
