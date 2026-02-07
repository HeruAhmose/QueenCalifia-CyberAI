# Git hooks

Install hooks:

```bash
make hooks
```

By default, `pre-push` runs `make test`.

To also run the Docker-based Grafana webhook smoke test:

```bash
export QC_PREPUSH_SMOKETEST=1
git push
```
