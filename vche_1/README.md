# VERITAS Replication Encoding (REP) -- vche_1/

This folder contains the sources to implement the Replication Encoding and Authenticator (REP) presented in Section 4 of the paper.

Please refer to the paper for the description of the encoding (Sec 4.1) and the authenticator (Sec 4.2).  

The structure of the folders follows the same one as Lattigo's implementation of BFV. 


Test:

```
go test -run=10 -bench=.
```