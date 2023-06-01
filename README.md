# otx-sighash-lock

otx-sighash-lock is a smart contract (lock script) based on the CKB blockchain. It enables signatures to only commit to a portion of the data in a transaction. 

Build contracts:

1. init submodules

```sh
git submodule init && git submodule update -r --init
```

2. build the shared binary secp256k1_blake2b_sighash_all_dual

```sh
cd ckb-miscellaneous-scripts && git submodule init && git submodule update -r --init && make install-tools &&make all-via-docker
```

3. build contract

``` sh
capsule build
```

Run tests:

``` sh
capsule test
```
