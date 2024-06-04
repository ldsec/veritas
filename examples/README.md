# VERITAS examples/

This folder contains the implementation of five use-cases to showcase the performance of VERITAS. Please refer to Section 6 of the paper for details about each use-case. 

- Disease Susceptibility  (Section 6.3.2)  
- Encrypted DNS search (Section 6.3.3)  
- Federated Learning gradients averaging (Section 6.3.5)  
- Neural Network inference for image classification (Section 6.3.4)  
- Ride-hailing matching (Section 6.3.1)  

We also provide a folder containing the notebooks used to generate the plots used in the paper (see veritas_analysis/)

Each example directory is organised with the baseline (i.e., the BFV standard pipeline), the REP encoding (VCHE1), the PE encoding (VCHE2), and their optimization with the closed-form PRF (CFPRF). It is organised with the following subdorectories: 
- baseline/: it comprises the BFV pipeline for the use case (main.go and/or benchmark_test.go).  
- vche_1/: it comprises the pipeline with REP encoding (main.go and/or benchmark_test.go).
- vche_2/: it comprises the pipeline with PE encoding (main.go and/or benchmark_test.go).
- data/: it comprises the useful data required to run the use-case. 
Additional subdirectories can be present to enable the PRF optimization of the encodings. 
An additional file ```<use-case>.go``` specifies the parametrization of the go-test for the ```<use-case>```.

The files ```main.go``` can be built by running the command:
```
go build main.go
```
And executed by:
```
./main
```

The benchmarks can be run by executing the command:
```
go test -run=10 -bench=. -timeout=60m | tee bench.out && benchstat -csv bench.out > bench.csv
```
Please specify the number of runs to be executed (i.e., 10) and the timeout (i.e., 60m). Note that this will require tee and benchstat to be installed.  

A script ```bench.sh``` enables to execute benchmarks of the encodings, their optimization when relevant (ReQ and PP) automatically. A similar script ```run.sh``` executes the main.go when relevant.  