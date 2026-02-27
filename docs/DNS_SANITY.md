# Post-bootstrap DNS sanity (ACME HTTP-01)

Before enabling the **Let’s Encrypt production** ClusterIssuer, verify that:

- The ingress controller has a reachable LoadBalancer address
- DNS for `staging_host` and `prod_host` resolves to the cluster
- `/.well-known/acme-challenge/` routes correctly (HTTP)

## GitHub Action

Run:
- Actions → **Post-bootstrap DNS sanity** → Run workflow

Inputs:
- `ingress_provider`: `nginxinc | traefik | haproxy`
- `ingress_class`: optional override
- `staging_host`, `prod_host`: your FQDNs

Required secret:
- `KUBECONFIG_B64`: base64 kubeconfig that can reach the cluster

The workflow deploys a temporary `qc-dns-sanity` ingress and curls:
`http://<host>/.well-known/acme-challenge/<token>`
then cleans itself up.


## Optional strict DNS → LB match

If you want the workflow to **fail** when DNS does not point *exactly* at the ingress LoadBalancer:

- Run the workflow with `strict_dns_match: true`

Behavior (strict):
- If ingress LB is an **IP**, DNS must return that same **A/AAAA** (and no CNAME).
- If ingress LB is a **hostname**, DNS must return a **CNAME chain** whose final target equals the LB hostname.
  (This will intentionally fail for ALIAS/ANAME records that return only A/AAAA.)

For `workflow_run` mode, you can set a repo variable:
- `QC_STRICT_DNS_MATCH=true|false`
