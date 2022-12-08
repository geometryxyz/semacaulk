// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { KeccakMT } from "./KeccakMT.sol";
import { BN254 } from "./BN254.sol";
import { TranscriptLibrary } from "./Transcrip.sol";
import { Types } from "./Types.sol";

contract Semacaulk is KeccakMT, BN254 {
    bytes32 public lagrangeTreeRoot;
    uint256 currentIndex;
    G1Point accumulator;

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

    // TranscriptLibrary.Transcript memory transcript = TranscriptLibrary.new_transcript(
    // );

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
        accumulator = G1Point(_accumulatorX, _accumulatorY);
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

        G1Point memory l = G1Point(_lagrangeLeafX, _lagrangeLeafY);

        G1Point memory newPoint = mul(l, vMinusZero);

        // 3. Update the accumulator
        accumulator = plus(accumulator, newPoint);

        // Increment the index
        currentIndex += 1;
    }

    function verifyTranscript() public pure returns(uint256, uint256) {
        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary.new_transcript();

        uint256 u1 = 100; 
        TranscriptLibrary.update_with_u256(transcript, u1);

        Types.G1Point memory pt = Types.G1Point(1, 2);
        TranscriptLibrary.update_with_g1(transcript, pt);

        uint256 challenge_1 =  TranscriptLibrary.get_challenge(transcript);

        uint256 u2 = 200; 
        TranscriptLibrary.update_with_u256(transcript, u2);

        uint256 challenge_2 =  TranscriptLibrary.get_challenge(transcript);

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
        G1Point memory A1 = G1Point(a1[0], a1[1]);
        G2Point memory A2 = G2Point(a2[0][0], a2[0][1], a2[1][0], a2[1][1]);

        G1Point memory B1 = G1Point(b1[0], b1[1]);
        G2Point memory B2 = G2Point(b2[0][0], b2[0][1], b2[1][0], b2[1][1]);

        G1Point memory C1 = G1Point(c1[0], c1[1]);
        G2Point memory C2 = G2Point(c2[0][0], c2[0][1], c2[1][0], c2[1][1]);

        return caulkPlusPairing(A1, A2, B1, B2, C1, C2);
    }

    function broadcastSignal(
    ) public {
    }

    function getCurrentIndex() public view returns (uint256) {
        return currentIndex;
    }

    function getAccumulator() public view returns (G1Point memory) {
        return accumulator;
    }
}
