# h-graph

Recursively resolve ALL Helm chart dependencies and container images.

## Problem

Helm only shows direct dependencies:

```bash
helm dependency list ./charts/chart-a                                              

NAME            VERSION REPOSITORY                                      STATUS
chart-b         0.1.0   file://../chart-b                               ok    
chart-d         0.1.0   file://../chart-d                               ok    
ibb-promstack   0.2.0   https://ibbproject.github.io/helm-charts/       ok 
```

**This breaks chart mirroring** for air-gapped environments - you mirror `chart-a` and `chart-b`, but miss `chart-c` and deployment fails.

## Solution

This tool provides recursive resolution:
- All transitive dependencies (chart-a -> chart-b -> chart-c -> ...)
- All container images across the entire dependency tree
- Works with remote repositories, local charts, and mixed scenarios

## Usage

### Resolve remote chart dependencies

<details>

```bash
./hg deps --chart ibb-promstack --repo https://ibbproject.github.io/helm-charts/ --format json
{
  "chart": {
    "name": "ibb-promstack",
    "version": "",
    "repository": "https://ibbproject.github.io/helm-charts/"
  },
  "dependencies": [
    {
      "name": "ibb-promstack",
      "version": "0.2.0",
      "repository": "https://ibbproject.github.io/helm-charts/"
    },
    {
      "name": "kube-prometheus-stack",
      "version": "67.9.0",
      "repository": "https://prometheus-community.github.io/helm-charts"
    },
    {
      "name": "kube-state-metrics",
      "version": "5.28.1",
      "repository": "https://prometheus-community.github.io/helm-charts"
    },
    {
      "name": "prometheus-node-exporter",
      "version": "4.43.1",
      "repository": "https://prometheus-community.github.io/helm-charts"
    },
    {
      "name": "grafana",
      "version": "8.8.6",
      "repository": "https://grafana.github.io/helm-charts"
    }
  ],
  "images": [
    {
      "name": "docker.io/grafana/grafana:11.4.1",
      "source": "grafana"
    },
    {
      "name": "quay.io/prometheus/node-exporter:v1.8.2",
      "source": "prometheus-node-exporter"
    },
    {
      "name": "quay.io/kiwigrid/k8s-sidecar:1.28.0",
      "source": "kube-prometheus-stack"
    },
    {
      "name": "docker.io/grafana/grafana:11.4.0",
      "source": "kube-prometheus-stack"
    },
    {
      "name": "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.14.0",
      "source": "kube-state-metrics"
    },
    {
      "name": "quay.io/prometheus-operator/prometheus-operator:v0.79.2",
      "source": "kube-prometheus-stack"
    }
  ],
  "summary": {
    "total_dependencies": 5,
    "total_images": 6,
    "generated_at": "2025-08-16T16:03:05.199626+03:00"
  },
  "skipped_charts": [
    {
      "name": "crds",
      "version": "0.0.0",
      "repository": ""
    }
  ]
}
```

</details>

### Resolve local chart dependencies

Note: Ensure that dependencies are built for local charts, via `helm dependency build/update`.

<details>

```bash
$ ./hg deps --chart ./charts/chart-a --format json
{
  "chart": {
    "name": "./charts/chart-a",
    "version": "",
    "repository": ""
  },
  "dependencies": [
    {
      "name": "chart-b",
      "version": "0.1.0",
      "repository": "file://../chart-b"
    },
    {
      "name": "chart-c",
      "version": "0.1.0",
      "repository": "file://../chart-c"
    },
    {
      "name": "chart-d",
      "version": "0.1.0",
      "repository": "file://../chart-d"
    },
    {
      "name": "ibb-promstack",
      "version": "0.2.0",
      "repository": "https://ibbproject.github.io/helm-charts/"
    },
    {
      "name": "kube-prometheus-stack",
      "version": "67.9.0",
      "repository": "https://prometheus-community.github.io/helm-charts"
    },
    {
      "name": "kube-state-metrics",
      "version": "5.28.1",
      "repository": "https://prometheus-community.github.io/helm-charts"
    },
    {
      "name": "prometheus-node-exporter",
      "version": "4.43.1",
      "repository": "https://prometheus-community.github.io/helm-charts"
    },
    {
      "name": "grafana",
      "version": "8.8.6",
      "repository": "https://grafana.github.io/helm-charts"
    }
  ],
  "images": [
    {
      "name": "quay.io/prometheus/node-exporter:v1.8.2",
      "source": "prometheus-node-exporter"
    },
    {
      "name": "nginx:1.16.0",
      "source": "chart-d"
    },
    {
      "name": "docker.io/grafana/grafana:11.4.0",
      "source": "kube-prometheus-stack"
    },
    {
      "name": "chart-a-init-container",
      "source": "/Users/buraksekili/projects/helm-dep-resolver/charts/chart-a"
    },
    {
      "name": "chart-c-image:1.16.0",
      "source": "chart-c"
    },
    {
      "name": "quay.io/kiwigrid/k8s-sidecar:1.28.0",
      "source": "kube-prometheus-stack"
    },
    {
      "name": "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.14.0",
      "source": "kube-state-metrics"
    },
    {
      "name": "chart-a-image:1.16.0",
      "source": "/Users/buraksekili/projects/helm-dep-resolver/charts/chart-a"
    },
    {
      "name": "docker.io/grafana/grafana:11.4.1",
      "source": "grafana"
    },
    {
      "name": "quay.io/prometheus-operator/prometheus-operator:v0.79.2",
      "source": "kube-prometheus-stack"
    }
  ],
  "summary": {
    "total_dependencies": 8,
    "total_images": 10,
    "generated_at": "2025-08-16T16:04:22.751236+03:00"
  },
  "skipped_charts": [
    {
      "name": "crds",
      "version": "0.0.0",
      "repository": ""
    }
  ]
}
```

</details>
