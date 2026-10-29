#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Removes what deploy.sh (or the Launch Stack button) created, and nothing
# else: the CloudFormation stack — the instance with its disk, the launch
# template, the security group, the key pair. The key files on the disk go
# with it; on EC2 they were sealed with the fleet's derived key (KNOWN_ISSUES
# 19), so they would have opened on another EC2 SEV-SNP guest of the same
# measurement and policy — the disk is what carries them, and it is deleted.
# The records under records/ stay.
#
# Usage: destroy.sh [--region REGION] [--stack NAME] [--yes]
set -euo pipefail
REGION="us-east-2"; STACK="vaultgenome"; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --region|-r) REGION="${2:?}"; shift 2;;
    --stack|-s) STACK="${2:?}"; shift 2;;
    --yes|-y) YES=1; shift;;
    -h|--help) sed -n '5,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
command -v aws >/dev/null 2>&1 || die "aws is needed"
aws sts get-caller-identity --query Arn --output text >/dev/null 2>&1 || die "aws is not signed in here"
STATUS="$(aws cloudformation --region "$REGION" describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
[ -n "$STATUS" ] || die "no stack named $STACK in $REGION"
TAGGED="$(aws cloudformation --region "$REGION" describe-stacks --stack-name "$STACK" --query 'Stacks[0].Tags[?Key==`app`]|[0].Value' --output text 2>/dev/null || true)"
[ "$TAGGED" = vaultgenome ] || die "the stack $STACK in $REGION is not one deploy.sh created (no app=vaultgenome tag); delete it by hand if you mean it"
ID="$(aws cloudformation --region "$REGION" describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text 2>/dev/null || true)"
if [ "$YES" != 1 ]; then
  printf 'Delete the stack %s in %s (instance %s, status %s)? Its disk and the key files on it go with it. [y/N] ' "$STACK" "$REGION" "${ID:-?}" "$STATUS"
  read -r answer; case "$answer" in y|Y|yes) ;; *) echo "kept"; exit 0;; esac
fi
cfn() { aws cloudformation --region "$REGION" "$@"; }
cfn delete-stack --stack-name "$STACK" || die "could not start deleting the stack $STACK"
if ! cfn wait stack-delete-complete --stack-name "$STACK" 2>/dev/null; then
  # A resource whose creation was cancelled (a stack that failed early)
  # can refuse to delete with an internal error; the stack is deleted
  # without it, and whatever it names is removed by hand below.
  FAILED="$(cfn describe-stack-events --stack-name "$STACK" --query 'StackEvents[?ResourceStatus==`DELETE_FAILED` && LogicalResourceId!=`'"$STACK"'`].LogicalResourceId' --output text 2>/dev/null | tr '\t' ' ' || true)"
  [ -n "$FAILED" ] || die "the stack $STACK did not finish deleting; see its events (aws cloudformation describe-stack-events --stack-name $STACK)"
  echo "  $STACK: retrying without $FAILED, which refused to delete"
  # shellcheck disable=SC2086
  cfn delete-stack --stack-name "$STACK" --retain-resources $FAILED || die "could not retry deleting the stack $STACK"
  cfn wait stack-delete-complete --stack-name "$STACK" || die "the stack $STACK did not finish deleting on the retry; see its events"
  case " $FAILED " in *" KeyPair "*) aws ec2 --region "$REGION" delete-key-pair --key-name "vg-$STACK" >/dev/null 2>&1 || true;; esac
fi
echo "removed the stack $STACK from $REGION; the records under $(cd "$(dirname "$0")" && pwd)/records stay"
