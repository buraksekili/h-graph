```bash
$ go build -o hg .

$ ./hg deps \
  --name ibb-promstack \
  --repo-name ibbproject \
  --repo-url https://ibbproject.github.io/helm-charts/ \
  --version 0.2.0 \
  --format json | jq

2025/08/14 15:19:25 WARNING: This chart or one of its subcharts contains CRDs. Rendering may fail or contain inaccuracies.
2025/08/14 15:19:29 WARNING: This chart or one of its subcharts contains CRDs. Rendering may fail or contain inaccuracies.
{
  "chart": {
    "name": "ibb-promstack",
    "version": "0.2.0",
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
      "name": "quay.io/prometheus-operator/prometheus-operator:v0.79.2",
      "source": "kube-prometheus-stack"
    },
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
    }
  ],
  "summary": {
    "total_dependencies": 5,
    "total_images": 6,
    "generated_at": "2025-08-14T15:19:35.883468+03:00"
  }
}
```
