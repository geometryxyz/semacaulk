# Trusted Setup

Semacaulk requires a [securely run trusted
setup](https://eprint.iacr.org/2017/1050.pdf). Specifically, for a capacity of
\\(2^n\\) elements, it requires \\(2^n + 1\\) \\({g_1}^{\tau}\\) points and
\\(2^n\\) \\({g_2}^{\tau}\\) points where \\(\tau\\) is highly unlikely to be
known but \\({g_1}^{\tau}\\) and \\({g_2}^{\tau}\\) can be generated via a
multi-party ceremony. As long as one participant does not reveal and destroys
the secret so-called toxic waste that they  use, the entire ceremony is secure.

For compatibility with Ethereum, Semacaulk is built on the BN254 curve. As
such, the output of the [Perpetual Powers of
Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau)
ceremony can be used. The outputs of this ceremony include up to \\(2^{28}\\)
\\({g_1}^{\tau}\\) and \\({g_2}^{\tau}\\) points. If Semacaulk is to be used on
a different elliptic curve, a different trusted setup must be used.

For the sake of convenience, we recommend the trusted setup output from Hermez
Network, which consist of the 54th contribution of Perpetual Powers of Tau (PPOT) with
a random beacon. These files can be downloaded from [this
page](https://github.com/iden3/snarkjs#7-prepare-phase-2). (You may also use
the latest contribution to PPOT, but at the time of writing, a tool to parse
and convert it has not yet been written.)

Note that the [Aztec Ignition ceremony
output](https://github.com/AztecProtocol/ignition-verification/blob/master/Transcript_spec.md)
is not sufficient for Semacaulk as only provides 1 `tauG2` point, while
Semacaulk requires as many `tauG2` points as the maximum desired capacity of
the accumulator. 
