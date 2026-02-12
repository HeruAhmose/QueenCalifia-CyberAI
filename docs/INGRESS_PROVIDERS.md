# Ingress providers (one toggle)

Default: NGINX Inc KIC

Switch provider by setting one value:
- helm/queen-califia/values.yaml: ingress.provider: nginxinc|traefik|haproxy
or via GitHub Actions bootstrap inputs (QC_INGRESS_PROVIDER)

Notes:
- Traefik HTTP->HTTPS redirect is best done globally (or via Middleware). If you set:
  ingress.traefik.redirectMiddleware, the chart will add the router.middlewares annotation (requires CRDs).
- HAProxy redirect is controlled by haproxy.org/ssl-redirect annotations.
