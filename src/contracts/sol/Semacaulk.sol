// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { KeccakMT } from "./KeccakMT.sol";
import { BN254 } from "./BN254.sol";
import { TranscriptLibrary } from "./Transcript.sol";
import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";
import { Verifier } from "./Verifier.sol";

contract Semacaulk is KeccakMT, BN254, Verifier {
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
     *  e = require('ethers')
     *  (
     *      BigInt(e.utils.solidityKeccak256(['string'], ['Semacaulk'])) %
     *          BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
     *  ).toString(16)
     */
    uint256 NOTHING_UP_MY_SLEEVE_ZERO = 
        uint256(keccak256(abi.encodePacked('Semacaulk'))) % Constants.PRIME_R;

    mapping (uint256 => bool) public nullifierHashHistory;

    // Custom errors
    error RootMismatch(bytes32 _generatedRoot);
    error NullifierHashAlreadySeen(uint256 _nullifierHash);
    error InvalidProof();

    // Events
    event InsertIdentity(uint256 indexed _index, uint256 indexed _identityCommitment);
    event BroadcastSignal(uint256 indexed _signalHash, uint256 indexed _externalNullifier);

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

        // 1. Verify that _lagrangeLeaf is a leaf of the tree at currentIndex
        bytes32 generatedRoot = genRootFromPath(
            index,
            lagrangeLeaf,
            _lagrangeMerkleProof
        );

        if (generatedRoot != lagrangeTreeRoot) {
            revert RootMismatch({ _generatedRoot: generatedRoot });
        }

        // 2. Compute (v - zero) * Li_comm
        uint256 n = Constants.PRIME_R;
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

    function broadcastSignal(
        bytes memory _signal,
        Types.Proof memory proof,
        uint256 _nullifierHash,
        uint256 _externalNullifier
    ) public {
        // Check whether the nullifier hash has been seen
        if (nullifierHashHistory[_nullifierHash]) {
            revert NullifierHashAlreadySeen({ _nullifierHash: _nullifierHash });
        }

        uint256 signalHash = hashSignal(_signal);

        uint256[3] memory publicInputs;
        publicInputs[0] = _externalNullifier;
        publicInputs[1] = _nullifierHash;
        publicInputs[2] = signalHash;

        // Verify the proof and revert if it is invalid
        bool isValid = verify(proof, getAccumulator(), publicInputs);
        if (!isValid) {
            revert InvalidProof();
        }

        // Store the nullifier hash to prevent double-signalling
        nullifierHashHistory[_nullifierHash] = true;

        emit BroadcastSignal(signalHash, _externalNullifier);
    }

    /*
     * Hash a bytes array with Keccak256 and shift the result by 8 bits so that
     * it can fit within the BN254 field size.
     * @param _signal The signal to hash
     */
    function hashSignal(bytes memory _signal) internal pure returns (uint256) {
        return uint256(keccak256(_signal)) >> 8;
    }

    function getCurrentIndex() public view returns (uint256) {
        return currentIndex;
    }

    function getAccumulator() public view returns (Types.G1Point memory) {
        return accumulator;
    }
}
