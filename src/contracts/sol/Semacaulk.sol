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

    // Events
    event InsertIdentity(uint256 indexed _index, uint256 indexed _identityCommitment);

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
        uint256 index = currentIndex;
        bytes32 lagrangeLeaf = keccak256(abi.encodePacked(_lagrangeLeafX, _lagrangeLeafY));

        // 1. Verify that _lagrangeLeaf exists in the lagrange tree at index currentIndex
        bytes32 generatedRoot = genRootFromPath(
            index,
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
        currentIndex = index + 1;

        emit InsertIdentity(index, _identityCommitment);
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
