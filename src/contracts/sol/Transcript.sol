// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Types } from "./Types.sol";

library TranscriptLibrary {
    // The scalar field
    uint256 constant PRIME_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 constant NUM_TRANSCRIPT_BYTES = 1248; // TODO: calculate this amount

    struct Transcript {
        bytes data;
        bytes32 currentChallenge;
        uint32 challengeCounter;
    } 

    /**
     * Instantiate a transcript and calculate the initial challenge, from which
     * other challenges are derived.
     * Resembles the preamble round in the Plonk prover
     */
    function newTranscript()
        internal
        pure
        returns (Transcript memory transcript)
    {
        transcript.currentChallenge = computeInitialChallenge();
        transcript.challengeCounter = 0;
        bytes memory transcriptDataPointer;
        bytes32 transcriptData = transcript.currentChallenge;
        uint256 totalTranscriptBytes = NUM_TRANSCRIPT_BYTES;
        assembly {
            transcriptDataPointer := mload(0x40)
            mstore(0x40, add(transcriptDataPointer, totalTranscriptBytes))
            // Update the length of transcript.data
            mstore(transcriptDataPointer, 0x20)
            // Insert current challenge
            mstore(add(transcriptDataPointer, 0x20), transcriptData)
        }
        transcript.data = transcriptDataPointer;
    }

    function computeInitialChallenge() internal pure returns (bytes32 challenge) {
        uint256 x = 0;
        return bytes32(x);
    }

    function updateWithU256(Transcript memory self, uint256 value) internal pure {
        bytes memory dataPtr = self.data;
        assembly {
            // update length of transcript data
            let array_length := mload(dataPtr)
            mstore(dataPtr, add(0x20, array_length))
            // insert new 32-byte value at the end of the array
            mstore(add(dataPtr, add(array_length, 0x20)), value)
        }
    }

    function updateWithG1(Transcript memory self, Types.G1Point memory p) internal pure {
        bytes memory dataPtr = self.data;
        assembly {
            // update length of self.data
            let array_length := mload(dataPtr)
            mstore(dataPtr, add(0x40, array_length))

            // insert new values to the end of the array
            mstore(add(dataPtr, add(array_length, 0x20)), mload(p))            // x cord
            mstore(add(dataPtr, add(array_length, 0x40)), mload(add(p, 0x20))) // y cord
        }
    }

    function round1(
        Transcript memory transcript, 
        Types.Proof memory proof,
        uint256[3] memory publicInputs
    ) internal pure {
        updateWithU256(transcript, publicInputs[0]);
        updateWithU256(transcript, publicInputs[1]);
        updateWithU256(transcript, publicInputs[2]);
        updateWithG1(transcript, proof.commitments.w0);
        updateWithG1(transcript, proof.commitments.key);
        updateWithG1(transcript, proof.commitments.w1);
        updateWithG1(transcript, proof.commitments.w2);
    }

    function round2(
        Transcript memory transcript, 
        Types.Proof memory proof
    ) internal pure {
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.quotient);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.zi);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.ci);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.u_prime);
    }

    function round3(
        Transcript memory transcript, 
        Types.Proof memory proof
    ) internal pure {
        TranscriptLibrary.updateWithG2(transcript, proof.commitments.w);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.h);
    }

    function round4(
        Transcript memory transcript, 
        Types.Proof memory proof
    ) internal pure {
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w0_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w0_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w0_2);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w1_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w1_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w1_2);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w2_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w2_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w2_2);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.key_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.key_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.q_mimc);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.mimc_cts);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.quotient);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.u_prime);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.p1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.p2);
    }

    function round5(
        Transcript memory transcript, 
        Types.Proof memory proof
    ) internal pure {
        TranscriptLibrary.updateWithG1(transcript, proof.multiopenProof.f_cm);
    }

    function updateWithG2(Transcript memory self, Types.G2Point memory p) internal pure {
        bytes memory dataPtr = self.data;
        assembly {
            // update length of self.data
            let array_length := mload(dataPtr)
            mstore(dataPtr, add(0x80, array_length))

            // insert new values to the end of the array
            mstore(add(dataPtr, add(array_length, 0x20)), mload(add(p, 0x20))) // x1 cord
            mstore(add(dataPtr, add(array_length, 0x40)), mload(p))            // x0 cord
            mstore(add(dataPtr, add(array_length, 0x60)), mload(add(p, 0x60))) // y1 cord
            mstore(add(dataPtr, add(array_length, 0x80)), mload(add(p, 0x40))) // y0 cord
        }
    }

    function resetToBytes32(Transcript memory self, bytes32 value) internal pure {
        bytes memory dataPtr = self.data;
        {
            assembly {
                mstore(dataPtr, 0x20)
                mstore(add(dataPtr, 0x20), value)
            }
        }
    }

    function getChallenge(Transcript memory self) internal pure returns (uint256) {
        bytes32 challenge;
        bytes memory dataPtr = self.data;
        assembly {
            let length := mload(dataPtr)
            challenge := keccak256(add(dataPtr, 0x20), length)
        }
        self.currentChallenge = challenge;
        // Reset self.data by setting length to 0x20 and updating the first element
        {
            assembly {
                mstore(dataPtr, 0x20)
                mstore(add(dataPtr, 0x20), challenge)
            }
        }
        assembly {
            challenge := mod(challenge, PRIME_R)
        }
        return uint256(challenge);
    }
}
