# Cloud kubeconfig + DNS (copy/paste)

## AWS EKS
$env:AWS_REGION="us-east-1"
$env:EKS_CLUSTER="YOUR_CLUSTER"
aws eks update-kubeconfig --region $env:AWS_REGION --name $env:EKS_CLUSTER
kubectl get nodes

# NGINX Inc KIC service address
kubectl -n nginx-ingress get svc -l app.kubernetes.io/instance=nginx-ingress `
  -o jsonpath="{.items[0].status.loadBalancer.ingress[0].hostname}{.items[0].status.loadBalancer.ingress[0].ip}"

Create Route53 records for:
- staging.YOURDOMAIN.com
- YOURDOMAIN.com
pointing at the LB hostname/IP (ALIAS/CNAME based on your setup).

## GCP GKE
$env:GCP_PROJECT="YOUR_PROJECT"
$env:GCP_REGION="us-central1"
$env:GKE_CLUSTER="YOUR_CLUSTER"
gcloud config set project $env:GCP_PROJECT
gcloud container clusters get-credentials $env:GKE_CLUSTER --region $env:GCP_REGION
kubectl get nodes

kubectl -n nginx-ingress get svc -l app.kubernetes.io/instance=nginx-ingress `
  -o jsonpath="{.items[0].status.loadBalancer.ingress[0].ip}"

Create Cloud DNS A record(s) to the external IP.

## Azure AKS
$env:AZ_RG="YOUR_RG"
$env:AKS_CLUSTER="YOUR_CLUSTER"
az aks get-credentials --resource-group $env:AZ_RG --name $env:AKS_CLUSTER --overwrite-existing
kubectl get nodes

kubectl -n nginx-ingress get svc -l app.kubernetes.io/instance=nginx-ingress `
  -o jsonpath="{.items[0].status.loadBalancer.ingress[0].ip}"

Create Azure DNS A/CNAME record(s) to the external IP/hostname.
