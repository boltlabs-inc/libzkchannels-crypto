
This repository contains two crates that compose the cryptographic requirements for the zkChannels protocol. 

__`zkchannels-crypto`__ is a general-purpose implementation of Pointcheval-Sanders signatures with efficient protocols and Pedersen commitments. The efficient protocols include zero-knowledge proofs of a signature and of the opening of a commitment; the library can also chain together proofs with linear relationships and range constraints on the underlying elements.

__`zkabacus-crypto`__ defines and implements a public, misuse-resistant API for the cryptographic components of the zkAbacus protcol (the off-chain component of zkChannels), including documentation of how inputs must be checked in the non-cryptographic component. 
