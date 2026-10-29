#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Publishes template.json where the Launch Stack button can read it: the
# CloudFormation console's quick-create link takes a template from Amazon
# S3 only, not from GitHub. The bucket is a maintainer's, public for the
# template alone; the object published is byte for byte the committed
# template (`--check` fetches it back and compares, which the kit does
# before it trusts the button's link).
#
#   publish-template.sh --bucket NAME [--region REGION] [--create]   # upload template.json as template.json and template-<release>.json
#   publish-template.sh --bucket NAME [--region REGION] --check      # the published template.json equals the committed one
#
# --create makes the bucket (block-public-access off for it, a policy
# that lets anyone read template*.json, nothing else). Prints the
# quick-create link for the README.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BUCKET=""; REGION="us-east-2"; CREATE=0; CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bucket|-b) BUCKET="${2:?}"; shift 2;;
    --region|-r) REGION="${2:?}"; shift 2;;
    --create) CREATE=1; shift;;
    --check) CHECK=1; shift;;
    -h|--help) sed -n '5,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[ -n "$BUCKET" ] || die "--bucket is required"
command -v aws >/dev/null 2>&1 || die "aws is needed"
TEMPLATE="$HERE/template.json"
URL="https://s3.$REGION.amazonaws.com/$BUCKET/template.json"
RELEASE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Parameters"]["Release"]["Default"])' "$TEMPLATE")"
if [ "$CHECK" = 1 ]; then
  TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
  curl -fsSL -o "$TMP" "$URL" || die "the published template could not be fetched from $URL"
  cmp -s "$TMP" "$TEMPLATE" && { echo "the published template at $URL is the committed template.json"; exit 0; }
  die "the published template at $URL differs from the committed template.json: publish it again"
fi
"$HERE/make-template.sh" --check >/dev/null || die "template.json is stale: run make-template.sh and commit it before publishing"
aws sts get-caller-identity --query Arn --output text >/dev/null 2>&1 || die "aws is not signed in here"
if [ "$CREATE" = 1 ]; then
  if [ "$REGION" = us-east-1 ]; then aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null
  else aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null; fi
  aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false"
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"VaultGenomeTemplate\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/template*.json\"}]}"
  echo "bucket $BUCKET made in $REGION: public read of template*.json, nothing else"
fi
for key in template.json "template-$RELEASE.json"; do
  aws s3 cp --region "$REGION" --content-type application/json --only-show-errors "$TEMPLATE" "s3://$BUCKET/$key"
done
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
curl -fsSL -o "$TMP" "$URL" && cmp -s "$TMP" "$TEMPLATE" || die "the template was uploaded but $URL does not serve it byte for byte"
echo "published: $URL (and template-$RELEASE.json beside it), equal to the committed template.json"
echo
echo "the quick-create link (the Launch Stack button):"
echo "https://$REGION.console.aws.amazon.com/cloudformation/home?region=$REGION#/stacks/create/review?templateURL=$URL&stackName=vaultgenome"
