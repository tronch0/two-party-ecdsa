# two-party-ecdsa
Fast Secure Two-Party ECDSA Signing based on [Yehuda Lindell's work](https://eprint.iacr.org/2017/552.pdf).

## Run the example
```bash
$ go run main.go
```
## TODO
1. [ ] Add alternative implementation to paillier: add El Gamal in the exponent
2. [ ] Add proofs to the communication between the parties 
3. [ ] Implement party as a separate process and communicate over libp2p

## A word of caution
This library was created primarily for education purposes. You should **NOT USE THIS CODE IN PRODUCTION SYSTEMS**. 
