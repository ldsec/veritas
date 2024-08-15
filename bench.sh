#!/bin/bash
SUBDIRS="$(find . -mindepth 1 -maxdepth 1 -type d)"
RUNS=10

echo "Running all benchmarks for single BFV operations"

for SUBDIR in $SUBDIRS
do
  echo "${SUBDIR##*/}"
  cd "$SUBDIR"
  echo "" > bench.out
  for ((i=1;i<=RUNS;i++))
  do
	  echo -e "\tRun #$i"
	  go test -bench="^BenchmarkVCHE" -run="^$" -timeout=60m  | tee -a "bench.out"
  done
  benchstat -format csv bench.out > bench.csv # Aggregate all runs
  cd -
done
