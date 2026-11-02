#!/bin/sh
# Retry `oci compute instance launch` across all ADs until A1 capacity appears.
# Usage: oci-launch-retry.sh <name> <ssh_pubkey_file_or_NONE>
# Requires ~/.oci/config + env: C (compartment ocid), SUBNET, IMAGE.
set -u
NAME="$1"
KEYFILE="$2"
: "${C:?compartment ocid}" "${SUBNET:?subnet ocid}" "${IMAGE:?image ocid}"

ADS=$(oci iam availability-domain list -c "$C" --query 'data[].name' --raw-output \
      | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)))')
echo "ADs: $ADS"

SSH_ARG=""
if [ "$KEYFILE" != "NONE" ]; then
  SSH_ARG="--metadata {\"ssh_authorized_keys\":\"$(cat "$KEYFILE")\"}"
fi

i=0
while :; do
  i=$((i+1))
  for AD in $ADS; do
    echo "[attempt $i] $NAME in $AD $(date +%H:%M:%S)"
    # shellcheck disable=SC2086
    OUT=$(oci compute instance launch \
      --compartment-id "$C" \
      --availability-domain "$AD" \
      --shape VM.Standard.A1.Flex \
      --shape-config '{"ocpus":1,"memoryInGBs":6}' \
      --image-id "$IMAGE" \
      --subnet-id "$SUBNET" \
      --assign-public-ip true \
      --display-name "$NAME" \
      $SSH_ARG 2>&1)
    if echo "$OUT" | grep -q '"id"'; then
      echo "$OUT" > "/tmp/launch-$NAME.json"
      echo "SUCCESS: $NAME launched in $AD"
      exit 0
    fi
    echo "$OUT" | grep -oE 'Out of capacity[^"]*|"code": "[^"]*"' | head -2
  done
  sleep 75
done
