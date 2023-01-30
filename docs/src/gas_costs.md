# Gas costs

An insertion (via `insertIdentity()` costs around 68k gas.

`broadcastSignal()`, which includes proof verification, costs 355k gas.

By contrast, a Tornado Cash deposit (which involves inserting a leaf to a
Merkle tree) costs [907787
gas](https://etherscan.io/tx/0x6f60a4aa7058dab153a859adfb139362d4bc395145528371ed90b127e528c7e7)
and a withdrawal (which involves a Groth16 verification step) costs [327188
gas](https://etherscan.io/tx/0xf2eb3005bf1d1866b4778d6b3686aaed64f8c6b015d2e998855598226223b613).
