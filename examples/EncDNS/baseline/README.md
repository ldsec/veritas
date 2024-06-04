# BFVencryptedDNS

This repository implements a simple database DNS lookup  under BFV encryption.  
The code is inspired from the example presented in HElib [1].  

The list of website comes from a subset of the Kaggle Alexa Top 1 Million Sites [2].

Modifications were required to work with Lattigo:
  - Bit-wise representation
  - Drop the Little Fermat Lemma in favour of a XOR
  - Use valid crypto parameters for BFV
  - Fully packed version reducing the overhead
  - Extend to world countries

[[1]](https://github.com/homenc/HElib/tree/master/examples/BGV_country_db_lookup) HElib country lookup example in BGV
[[2]](https://www.kaggle.com/cheedcheed/top1m?select=top-1m.csv) Kaggle Alexa Top 1 Million Sites
