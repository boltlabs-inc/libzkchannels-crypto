
This repository contains two crates that compose the cryptographic requirements for the zkChannels protocol. 

__`zkchannels-crypto`__ is a general-purpose implementation of Pointcheval-Sanders signatures with efficient protocols and Pedersen commitments. The efficient protocols include zero-knowledge proofs of knowledge of a signature and of the opening of a commitment. The library supports proving AND statements with respect to signatures and commitments, including proving partial openings, linear relationships, and range constraints on the underlying commitment openings.

__`zkabacus-crypto`__ defines and implements a public, misuse-resistant API for the cryptographic components of the zkAbacus protcol (the off-chain component of zkChannels), including documentation of how inputs must be checked in the non-cryptographic component. 
