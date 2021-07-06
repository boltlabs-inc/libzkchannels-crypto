# zkchannels-crypto

This crate contains cryptographic primitives instantiated over the pairing-friendly curve
BLS12-381:
 
- Pedersen commitments, instantiated in `G1` and `G2`.
- Pointcheval Sanders signatures and blind signatures (CT-RSA 2016).
- Schnorr-style zero-knowledge proofs of knowledge of Pointcheval-Sanders signatures and of the opening of Pedersen commitments. The proof library also includes functionality for building conjunctions of proofs and applying constraints (including linear relationships, partial openings, and range constraints) on elements in proofs.

For more details, please build the Rust documentation:
```
$ cargo doc --all-features --no-deps --open
```