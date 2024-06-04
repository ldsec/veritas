# VERITAS Polynomial Encoding (PE) -- vche_2/

This folder contains the sources to implement the Polynomial Encoding (PE) presented in Section 5 of the paper.

Please refer to the paper for the description of the encoding, the authenticator, the Polynomial Protocol (PP) and Re-quadratization (ReQ) optimisations (Sec 5.1, 5.2, 5.3, and 5.4 resp.).  

The structure of the folders follows the same one as Lattigo's implementation of BFV. 

Test:

```
go test -run=10 -bench=.
```