gcloud compute ssh wg-core-free --project "$PROJECT_ID" --zone "$ZONE" 

gcloud compute ssh wg-core-free --project "$PROJECT_ID" --zone us-west1-b --command \
"sudo journalctl -u wg-core -n 200 --no-pager"

gcloud compute ssh wg-core-free --project "$PROJECT_ID" --zone us-west1-b --command \
"sudo journalctl -u wg-entry -n 200 --no-pager"

scripts/deploy-core-vm.sh   --project "$PROJECT_ID"   --vm-name "$VM_NAME"   --zone "$ZONE"   --google-oidc-client-id "$GOOGLE_OIDC_CLIENT_ID"   --google-oidc-client-secret "$GOOGLE_OIDC_CLIENT_SECRET"   --google-oidc-redirect-uri "$GOOGLE_OIDC_REDIRECT_URI"