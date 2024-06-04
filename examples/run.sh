#!/bin/bash
# Usage: cd examples/[USE-CASE]; ./run.sh
SUBDIRS="$(find . -mindepth 1 -maxdepth 1 -type d)"

echo "Running all 'main.go' for use case ${PWD##*/}"

for SUBDIR in $SUBDIRS; do
  echo "================================"
  echo "${SUBDIR##*/}"
  echo "--------------------------------"
  cd "$SUBDIR"
  go run . -timeout=60m
  cd -
done
