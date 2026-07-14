package resolver

import (
	"path/filepath"
	"testing"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// newResolver builds a Resolver with a nop logger so tests stay quiet.
func newResolver(t *testing.T) *Resolver {
	t.Helper()
	r := NewResolver("json")
	r.SetQuietMode(true)
	return r
}

// chartWithImage is a minimal in-memory chart rendering one Deployment image.
func chartWithImage(name, image string) *chart.Chart {
	return &chart.Chart{
		Metadata: &chart.Metadata{
			Name:    name,
			Version: "0.1.0",
		},
		Templates: []*chart.File{
			{
				Name: "templates/deployment.yaml",
				Data: []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + name + "\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: " + image + "\n"),
			},
		},
	}
}

// TestCoalesceValuesMergesOverrides confirms renderValues overlay chart defaults.
func TestCoalesceValuesMergesOverrides(t *testing.T) {
	ch := &chart.Chart{
		Metadata: &chart.Metadata{Name: "x", Version: "0.1.0"},
		Values: map[string]interface{}{
			"sidecar": map[string]interface{}{"enabled": false},
		},
	}

	got, err := coalesceValues(ch, map[string]interface{}{
		"sidecar": map[string]interface{}{"enabled": true},
	})
	if err != nil {
		t.Fatalf("coalesceValues: %v", err)
	}

	sc, ok := got["sidecar"].(map[string]interface{})
	if !ok {
		t.Fatalf("sidecar missing or wrong type: %#v", got["sidecar"])
	}
	if sc["enabled"] != true {
		t.Fatalf("override not applied: %#v", sc)
	}
}

// TestExtractImagesHonorsValues proves a values-gated image only appears when
// renderValues enable it.
func TestExtractImagesHonorsValues(t *testing.T) {
	chartPath, err := filepath.Abs(filepath.Join("..", "..", "charts", "chart-values"))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	loaded, err := loader.Load(chartPath)
	if err != nil {
		t.Fatalf("load chart-values: %v", err)
	}

	// defaults only: sidecar disabled, so only the main image renders
	r := newResolver(t)
	dep := &ResolvedDependency{
		Name: "chart-values",
		node: &ChartCtx{Chart: loaded},
	}
	if err := r.extractImagesFromChart(dep); err != nil {
		t.Fatalf("extract with defaults: %v", err)
	}
	if _, ok := r.AllImages["docker.io/example/main:1.0.0"]; !ok {
		t.Errorf("main image missing with defaults: %v", r.AllImages)
	}
	if _, ok := r.AllImages["docker.io/example/sidecar:1.0.0"]; ok {
		t.Errorf("sidecar should not render with defaults: %v", r.AllImages)
	}

	// with renderValues enabling the sidecar, the gated image appears
	r2 := newResolver(t)
	r2.renderValues = map[string]interface{}{
		"sidecar": map[string]interface{}{"enabled": true},
	}
	dep2 := &ResolvedDependency{
		Name: "chart-values",
		node: &ChartCtx{Chart: loaded},
	}
	if err := r2.extractImagesFromChart(dep2); err != nil {
		t.Fatalf("extract with values: %v", err)
	}
	if _, ok := r2.AllImages["docker.io/example/sidecar:1.0.0"]; !ok {
		t.Errorf("sidecar image should render under renderValues: %v", r2.AllImages)
	}
}

// TestExtractImagesRecordsAliasProvenance confirms an aliased dependency's
// images are attributed to the alias, matching how helm routes values.
func TestExtractImagesRecordsAliasProvenance(t *testing.T) {
	r := newResolver(t)
	dep := &ResolvedDependency{
		Name:  "real-child",
		Alias: "aliased-child",
		node:  &ChartCtx{Chart: chartWithImage("real-child", "docker.io/example/child:1.0.0")},
	}
	if err := r.extractImagesFromChart(dep); err != nil {
		t.Fatalf("extract: %v", err)
	}

	chart, ok := r.imageToChart["docker.io/example/child:1.0.0"]
	if !ok {
		t.Fatalf("image missing from mapping: %v", r.imageToChart)
	}
	if chart != "aliased-child" {
		t.Errorf("provenance = %q, want aliased-child", chart)
	}
}

// TestParseManifestFileCoversCronJobAndReplicaSet confirms the newly added
// workload kinds are scanned for image references.
func TestParseManifestFileCoversCronJobAndReplicaSet(t *testing.T) {
	manifest := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: cj
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: app
              image: docker.io/example/cron:1.0.0
---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: rs
spec:
  template:
    spec:
      containers:
        - name: app
          image: docker.io/example/replica:1.0.0
`
	images := parseManifestFile(manifest, nil)
	for _, want := range []string{"docker.io/example/cron:1.0.0", "docker.io/example/replica:1.0.0"} {
		if _, ok := images[want]; !ok {
			t.Errorf("missing image %q from %v", want, images)
		}
	}
}
