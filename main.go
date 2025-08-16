package main

import (
	"fmt"
	"log"
	"os"

	"github.com/buraksekili/helm-dep-resolver/pkg/report"
	"github.com/buraksekili/helm-dep-resolver/pkg/resolver"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hg",
	Short: "A tool to analyze Helm chart dependencies and images.",
	Long:  `A powerful CLI tool built with Cobra to inspect Helm charts, list their dependencies, and visualize their dependency graph.`,
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

		if format != string(report.FormatJSON) && format != string(report.FormatText) {
			fmt.Printf("❌ Invalid format '%s'. Supported formats: %s, %s\n", format, report.FormatText, report.FormatJSON)
			return
		}

		resolver := resolver.NewResolver(format)

		resolved, err := resolver.Resolve(chart, version, repoURL)
		if err != nil {
			log.Fatalf("❌ Resolution failed: %v", err)
		}

		switch report.OutputFormat(format) {
		case report.FormatJSON:
			generator := report.NewGenerator(resolver)
			reportData := generator.Generate(chart, version, repoURL)
			if err := generator.OutputJSON(reportData); err != nil {
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
			for img := range resolver.AllImages {
				fmt.Println(img)
			}
		}
	},
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
