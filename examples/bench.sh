#!/bin/bash
# Usage: cd examples/[USE-CASE]; ../bench.sh
SUBDIRS="$(find . -mindepth 1 -maxdepth 1 -type d)"

echo "Running all benchmarks for use case ${PWD##*/}"

for SUBDIR in $SUBDIRS; do
  echo "================================"
  echo "${SUBDIR##*/}"
  echo "--------------------------------"
  cd "$SUBDIR"
  go test -run=1000 -bench=. -timeout=60m | tee bench.out && benchstat -format csv bench.out >bench.csv
  cd -
done
