package main

import (
	"fmt"
	"os"

	"github.com/buraksekili/h-graph/pkg/report"
	"github.com/buraksekili/h-graph/pkg/resolver"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "h-graph",
	Short: "A tool to analyze Helm chart dependencies and images.",
	Long:  `A CLI tool to resolve a Helm chart's full dependency tree, including all nested sub-charts, and discover every container image.`,
}

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Recursively resolves all chart dependencies and container images",
	Long: `Recursively resolves all chart dependencies and container images for a given chart.
Unlike helm dependency list which only shows direct dependencies, this command reveals 
the complete transitive dependency tree and extracts all container images across all 
dependency levels. Supports multiple chart sources: HTTP repositories, OCI registries, 
and local paths.`,
	Example: `  # Resolve remote chart dependencies
  hg deps --chart ibb-promstack --repo https://ibbproject.github.io/helm-charts/ --format json

  # Resolve local chart dependencies (ensure dependencies are built first)
  hg deps --chart ./charts/chart-a --format json`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: what happens if both repo and chart defined?
		// tip: fallback to reading remote
		repoURL, _ := cmd.Flags().GetString("repo")
		chart, _ := cmd.Flags().GetString("chart")
		version, _ := cmd.Flags().GetString("version")
		format, _ := cmd.Flags().GetString("format")

		if repoURL == "" && chart == "" {
			exitWithError(fmt.Errorf("both Repository URL and Path empty, one of them is required"))
		}

		if format != string(report.FormatJSON) && format != string(report.FormatText) {
			exitWithError(fmt.Errorf("❌ Invalid format '%s'. Supported formats: %s, %s\n", format, report.FormatText, report.FormatJSON))
		}

		err := runDeps(format, chart, version, repoURL)
		if err != nil {
			exitWithError(err)
		}
	},
}

func exitWithError(err error) {
	fmt.Printf("❌ Error: %v\n", err)
	os.Exit(1)
}

func runDeps(format, chart, version, repoURL string) error {
	resolver := resolver.NewResolver(format)

	resolved, err := resolver.Resolve(chart, version, repoURL)
	if err != nil {
		return fmt.Errorf("resolution failed: %v", err)
	}

	switch report.OutputFormat(format) {
	case report.FormatJSON:
		generator := report.NewGenerator(resolver)
		reportData := generator.Generate(chart, version, repoURL)
		if err := generator.OutputJSON(reportData); err != nil {
			return fmt.Errorf("failed to output JSON: %v", err)
		}
	default:
		fmt.Println("✅ Dependency resolution complete. Found unique dependencies:")
		fmt.Println("--------------------------------------------------")
		for _, dep := range resolved {
			fmt.Println(dep.String())
		}
		fmt.Println("\n🐳 Container Images:")
		fmt.Println("--------------------------------------------------")
		for img := range resolver.AllImages {
			fmt.Println(img)
		}
	}

	return nil
}

func init() {
	depsCmd.Flags().StringP("chart", "c", "", "Chart name")
	depsCmd.Flags().StringP("repo", "r", "", "Repository URL")
	depsCmd.Flags().StringP("version", "v", "", "Chart version")
	depsCmd.Flags().StringP("format", "f", string(report.FormatText), fmt.Sprintf("Output format (%s, %s)", report.FormatText, report.FormatJSON))
}

func main() {
	rootCmd.AddCommand(depsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
