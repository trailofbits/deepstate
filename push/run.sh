#!/usr/bin/env bash

set -eu

IMAGE_NAME="deepstate"
DEPLOY_BRANCHES="master"

# Only process first job in matrix (TRAVIS_JOB_NUMBER ends with ".1")
if [[ ! $TRAVIS_JOB_NUMBER =~ \.1$ ]]; then
  echo "Skipping deploy since it's not the first job in matrix"
  exit 0
fi

# Don't process pull requests
# $TRAVIS_PULL_REQUEST will be the PR number or "false" if not a PR
if [[ -n "$TRAVIS_PULL_REQUEST" ]] && [[ "$TRAVIS_PULL_REQUEST" != "false" ]]; then
  echo "Skipping deploy because it's a pull request"
  exit 0
fi

# Only process branches listed in DEPLOY_BRANCHES
BRANCHES_TO_DEPLOY=($DEPLOY_BRANCHES)
if [[ ! " ${BRANCHES_TO_DEPLOY} " =~ " ${TRAVIS_BRANCH} " ]]; then
  # whatever you want to do when arr contains value
  echo "Branches to deploy: ${DEPLOY_BRANCHES}"
  echo "Travis Branch: ${TRAVIS_BRANCH}"

  echo "Skipping deploy, not a branch to be deployed"
  exit 0
fi

if [ $? = 0 ]; then

  # Get absolute path of dir where run.sh is located
  SOURCE="${BASH_SOURCE[0]}"
  while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
    DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
  done
  export SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

  bash ${SCRIPTDIR}/build_image &&
  bash ${SCRIPTDIR}/publish

fi
