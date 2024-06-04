# VERITAS
This is an implementation of the VERITAS system described in the paper "VERITAS: Plaintext Encoders for Practical Verifiable Homomorphic Encryption" by Sylvain Chatel, Christian Knabenhans, Apostolos Pyrgelis, Carmela Troncoso, and Jean-Pierre Hubaux appearing in the Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security (CCS '24).  

## Description

VERITAS enables verifiability of homomorphic computations performed by a malicious-but-rational computing server. In particular, VERITAS implements encodings that enable the decryptor to verify the correctness of the executed operations. It is built on top of the [Lattigo](https://github.com/ldsec/lattigo/) BFV implementation.

VERITAS implements two encodings: 
- The Replication Encoding -- REP (VCHE1) -- See Section 4 of the paper.
- The Polynomial Encoding -- PE (VCHE2) -- See Section 5 of the paper.

## Dependencies
This system requires Go 1.15.7 or newer (tested on 1.15.7 and 1.17.3) with benchstat. It can be installed by running:
```
wget https://golang.org/dl/go1.17.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go get golang.org/x/perf/cmd/benchstat
```
Some additional requirements can be installed using the command:
```
apt-get install build-essential
```

This code was tested on Ubuntu Focal (20.04.3) and macOS Big Sur (11.5.2).  

## Code Organization

The code of VERITAS is organized in the following folders:

- 'bfv_generic' provides a wrapper of the Lattigo BFV
- 'examples' provides examples of use of VERITAS on five use-cases
- 'vche' provides encoding agnostic VERITAS components for BFV integration.  
- 'vche_1' provides the REP encoding source code
- 'vche_1_CFPRF' provides the tests for the REP encoding with PRF optimisation 
- 'vche_2' provides the REP encoding source code for the PE encoding 
- 'vche_2_CFPRF' provides the tests for the PE encoding with PRF optimisation 


## License
This software and its source code are licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Citing VERITAS
```
@inproceedings{chatel2024veritas,
  title={VERITAS: Plaintext Encoders for Practical Verifiable Homomorphic Encryption},
  author={Chatel, Sylvain and Knabenhans, Christian and Pyrgelis, Apostolos and Troncoso, Carmela and Hubaux, Jean-Pierre},
  year={2024},
  booktitle = {Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security},
  doi = {10.1145/3658644.3670282},
  url = {https://doi.org/10.1145/3658644.3670282},
  series = {CCS '24}
}
```
