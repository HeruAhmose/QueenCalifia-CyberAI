# Helm publishing

This repo supports publishing the Helm chart via GitHub Actions.

- **OCI (recommended):** pushes to `ghcr.io/<owner>/charts`
- **GitHub Pages (optional):** publishes an index on the `gh-pages` branch

## Release

Tag a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This will build/push images and publish the chart to OCI.

For GitHub Pages publishing, run the `release-helm` workflow manually and choose `pages` or `both`.
