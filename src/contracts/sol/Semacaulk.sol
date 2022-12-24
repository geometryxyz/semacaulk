// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { KeccakMT } from "./KeccakMT.sol";
import { BN254 } from "./BN254.sol";
import { TranscriptLibrary } from "./Transcript.sol";
import { Types } from "./Types.sol";

contract Semacaulk is KeccakMT, BN254 {
    bytes32 public lagrangeTreeRoot;
    uint256 currentIndex;
    Types.G1Point accumulator;

    /*
     * By setting the value of unset (empty) tree leaves to this
     * nothing-up-my-sleeve value, the authors demonstrate, via the property of
     * second-preimage resistance of Keccak256, that they do not have its
     * preimage and therefore cannot spend funds they do not own.
     * To reproduce this value, run the following in a JS console:
     *
     * TODO: should this be mod Fq instead of Fr?
     *
     *  e = require('ethers')
     *  (
     *      BigInt(e.utils.solidityKeccak256(['string'], ['Semacaulk'])) %
     *          BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
     *  ).toString(16)
     */
    uint256 NOTHING_UP_MY_SLEEVE_ZERO = 
        uint256(keccak256(abi.encodePacked('Semacaulk'))) % PRIME_R;

    // Custom errors
    error RootMismatch(bytes32 _generatedRoot);

    constructor(
        bytes32 _lagrangeTreeRoot,
        uint256 _accumulatorX,
        uint256 _accumulatorY
    ) {
        // TODO: range-check _lagrangeTreeRoot
        lagrangeTreeRoot = _lagrangeTreeRoot;

        // TODO: validate the point
        accumulator = Types.G1Point(_accumulatorX, _accumulatorY);
    }

    function insertIdentity(
        uint256 _identityCommitment,
        uint256 _lagrangeLeafX,
        uint256 _lagrangeLeafY,
        bytes32[] memory _lagrangeMerkleProof
    ) public {
        bytes32 lagrangeLeaf = keccak256(abi.encodePacked(_lagrangeLeafX, _lagrangeLeafY));

        // 1. Verify that _lagrangeLeaf exists in the lagrange tree at index currentIndex
        bytes32 generatedRoot = genRootFromPath(
            currentIndex,
            lagrangeLeaf,
            _lagrangeMerkleProof
        );

        if (generatedRoot != lagrangeTreeRoot) {
            revert RootMismatch({ _generatedRoot: generatedRoot });
        }

        // 2. Compute (v - zero) * Li_comm
        uint256 n = PRIME_R;
        uint256 negZero = mulmod(NOTHING_UP_MY_SLEEVE_ZERO, n - 1, n);
        uint256 vMinusZero = addmod(_identityCommitment, negZero, n);

        Types.G1Point memory l = Types.G1Point(_lagrangeLeafX, _lagrangeLeafY);

        Types.G1Point memory newPoint = mul(l, vMinusZero);

        // 3. Update the accumulator
        accumulator = plus(accumulator, newPoint);

        // Increment the index
        currentIndex += 1;
    }

    function verifyTranscript() public pure returns(uint256, uint256) {
        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary.newTranscript();

        uint256 u1 = 100; 
        TranscriptLibrary.updateWithU256(transcript, u1);

        Types.G1Point memory pt = Types.G1Point(1, 2);
        TranscriptLibrary.updateWithG1(transcript, pt);

        uint256 challenge_1 =  TranscriptLibrary.getChallenge(transcript);

        uint256 u2 = 200; 
        TranscriptLibrary.updateWithU256(transcript, u2);

        uint256 challenge_2 =  TranscriptLibrary.getChallenge(transcript);

        return (challenge_1, challenge_2);
    }

    /// @dev Temporary function that invokes pairing check
    function verifyProof(
        uint[2] memory a1,
        uint[2][2] memory a2,
        uint[2] memory b1,
        uint[2][2] memory b2,
        uint[2] memory c1,
        uint[2][2] memory c2
    ) public view returns (bool) {
        Types.G1Point memory A1 = Types.G1Point(a1[0], a1[1]);
        Types.G2Point memory A2 = Types.G2Point(a2[0][0], a2[0][1], a2[1][0], a2[1][1]);

        Types.G1Point memory B1 = Types.G1Point(b1[0], b1[1]);
        Types.G2Point memory B2 = Types.G2Point(b2[0][0], b2[0][1], b2[1][0], b2[1][1]);

        Types.G1Point memory C1 = Types.G1Point(c1[0], c1[1]);
        Types.G2Point memory C2 = Types.G2Point(c2[0][0], c2[0][1], c2[1][0], c2[1][1]);

        return caulkPlusPairing(A1, A2, B1, B2, C1, C2);
    }

    function pow7(
        uint256 val,
        uint256 p
    ) public pure returns (uint256) {
        uint256 result;
        uint256 x2;
        uint256 x4;
        uint256 x6;

        assembly {
            // Compute val^7
            x2 := mulmod(val, val, p)
            x4 := mulmod(x2, x2, p)
            x6 := mulmod(x4, x2, p)
            result := mulmod(x6, val, p)
        }
        return result;
    }

    function idNullifierGateEval(
        uint256 qMimc,
        uint256 w0,
        uint256 c,
        uint256 w0Gamma
    ) public pure returns (uint256) {
        uint256 p = PRIME_R;

        require(w0Gamma < p);

        // Let's say we have a gate defined as a + b = c.
        // In the full protocol, we'll have polynomial commitments [A], [B],
        // and [C], a random point x, and opening proofs that A(x) = a, B(x) =
        // b, and C(x) = c. After the verifier checks that these proofs are
        // valid, it also needs to check that the gate relation a + b = c is
        // fulfilled.

        // Note that the gate equations are modulo PRIME_R
        // TODO: is this correct?

        // For now, we skip the opening proofs and just test the gate relations.

        // Gate 1: q_mimc * ((w_0(X) + c(X)) ^ 7 - w_0(gammaX)) = 0
        // NOTE FROM WJ: I'm not sure where w0Gamma should come from, but for now let's
        // just take it as it is.

        uint256 w0_plus_c;
        uint256 negW0Gamma;

        assembly {
            // Compute -w0Gamma
            negW0Gamma := sub(p, w0Gamma)

            // Compute (w0 + c)
            w0_plus_c := addmod(w0, c, p)
        }

        // Compute (w0 + c)^7
        uint256 result = pow7(w0_plus_c, p);

        assembly {
            // Compute (w0 + c)^7 - w0Gamma
            result := addmod(result, negW0Gamma, p)

            // Compute qMimc * (w0 + c)^7 - w0Gamma
            result := mulmod(qMimc, result, p)
        }

        return result;
    }

    function idCommLrdEval(
        uint256 qMimc,
        uint256 w1,
        uint256 key,
        uint256 c,
        uint256 w1Gamma
    ) public pure returns (uint256) {
        uint256 p = PRIME_R;

        require(w1Gamma < p);

        uint256 w1_plus_key_plus_c;
        uint256 negW1Gamma;

        assembly {
            // Compute -w1Gamma
            negW1Gamma := sub(p, w1Gamma)

            // Compute (w1 + key + c)
            w1_plus_key_plus_c := addmod(w1, key, p)
            w1_plus_key_plus_c := addmod(w1_plus_key_plus_c, c, p)
        }

        // Compute (w1 + key + c) ^ 7
        uint256 result = pow7(w1_plus_key_plus_c, p);

        assembly {
            // Compute (w1 + key + c)^7 - w1Gamma
            result := addmod(result, negW1Gamma, p)

            // Compute qMimc * (w1 + key + c)^7 - w1Gamma
            result := mulmod(qMimc, result, p)
        }

        return result;
    }

    function keyConstantEval(
        uint256 qMimc,
        uint256 key,
        uint256 keyGamma
    ) public pure returns (uint256) {
        uint256 p = PRIME_R;

        uint256 result;
        uint256 negKeyGamma;

        require(keyGamma < p);

        assembly {
            // Compute -keyGamma
            negKeyGamma := sub(p, keyGamma)

            // Compute (key - keyGamma)
            result := addmod(key, negKeyGamma, p)

            // Compute qMimc * (key - keyGamma)
            result := mulmod(qMimc, result, p)
        }

        return result;
    }

    function keyCopyEval(
        uint256 l0,
        uint256 key,
        uint256 w0,
        uint256 w0Gamma91
    ) public pure returns (uint256) {
        uint256 p = PRIME_R;

        uint256 result;
        uint256 w0PlusW0Gamma91;
        uint256 negW0PlusW0Gamma91;

        assembly {
            // Compute w0 + w0Gamma91
            w0PlusW0Gamma91 := addmod(w0, w0Gamma91, p)

            // Compute -(w0 + w0Gamma91)
            negW0PlusW0Gamma91 := sub(p, w0PlusW0Gamma91)

            // Compute (key - w0 - w0Gamma91)
            result := addmod(key, negW0PlusW0Gamma91, p)

            // Compute l0 * (key - w0 - w0Gamma91)
            result := mulmod(l0, result, p)
        }

        return result;
    }

    function nullifierHashFinalEval(
        uint256 l0,
        uint256 nullifierHash,
        uint256 w2,
        uint256 w2Gamma91,
        uint256 key
    ) public pure returns (uint256) {
        uint256 p = PRIME_R;

        uint256 result;
        uint256 w2PlusW2Gamma91Plus2Key;
        uint256 negW2PlusW2Gamma91Plus2Key;
        uint256 twoKey;

        assembly {
            // Compute 2key
            twoKey := addmod(key, key, p)

            // Compute w2 + w2Gamma91 + 2key
            w2PlusW2Gamma91Plus2Key := addmod(w2, w2Gamma91, p)
            w2PlusW2Gamma91Plus2Key := addmod(w2PlusW2Gamma91Plus2Key, twoKey, p)

            // Compute -(w2 + w2Gamma91 + 2key)
            negW2PlusW2Gamma91Plus2Key := sub(p, w2PlusW2Gamma91Plus2Key)

            // Compute nullifierHash - w2 - w2Gamma91 - 2key
            result := addmod(nullifierHash, negW2PlusW2Gamma91Plus2Key, p)

            // Compute l0 * (nullifierHash - w2 - w2Gamma91 - 2key)
            result := mulmod(l0, result, p)
        }

        return result;
    }

    function broadcastSignal(
    ) public {
    }

    function getCurrentIndex() public view returns (uint256) {
        return currentIndex;
    }

    function getAccumulator() public view returns (Types.G1Point memory) {
        return accumulator;
    }
}
