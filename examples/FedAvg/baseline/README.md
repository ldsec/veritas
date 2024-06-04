# BFVaveraging

This repository implements the federated averaging of encrypted weights using the BFV scheme from Lattigo. 

Weights were obtained from the unofficial PyTorch implementation of McMahan FedAvg (thanks to Seok-Ju Hahn a.k.a. vaseline555 [1]).

We ran the TwoNN network on MNIST with 100 clients and an averaging accross 10 of them. 
We provide the .yaml file for consistency.

The bit quantization was on 16bits. 

 McMahan et al.'s paper "Communication-Efficient Learning of Deep Networks from Decentralized Data" - AISTATS 2017  
[[1]](https://github.com/vaseline555/Federated-Averaging-PyTorch) Seok-Ju Hahn re-implementation of FedAvg

 
