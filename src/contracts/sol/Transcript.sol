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
        // uint256 numPublicInputs;
    } 

    /**
     * Instantiate a transcript and calculate the initial challenge, from which other challenges are derived.
     *
     * Resembles the preamble round in the Plonk prover
     */
    function newTranscript()
        internal
        pure
        returns (Transcript memory transcript)
    {
        transcript.currentChallenge = computeInitialChallenge();
        transcript.challengeCounter = 0;
        // manually format the transcript.data bytes array
        // This is because we want to reserve memory that is greatly in excess of the array's initial size
        bytes memory transcriptDataPointer;
        bytes32 transcriptData = transcript.currentChallenge;
        uint256 totalTranscriptBytes = NUM_TRANSCRIPT_BYTES;
        assembly {
            transcriptDataPointer := mload(0x40)
            mstore(0x40, add(transcriptDataPointer, totalTranscriptBytes))
            // update length of transcript.data
            mstore(transcriptDataPointer, 0x20)
            // insert current challenge
            mstore(add(transcriptDataPointer, 0x20), transcriptData)
        }
        transcript.data = transcriptDataPointer;
        // transcript.numPublicInputs = numPublicInputs;
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
            // update length of transcript data
            let array_length := mload(dataPtr)
            mstore(dataPtr, add(0x40, array_length))
            // insert new 64-byte value at the end of the array
            mstore(add(dataPtr, add(array_length, 0x20)), mload(p)) // x cord
            mstore(add(dataPtr, add(array_length, 0x40)), mload(add(p, 0x20))) // y cord
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
        // reset self.data by setting length to 0x20 and update first element
        {
            assembly {
                mstore(dataPtr, 0x20)
                mstore(add(dataPtr, 0x20), challenge)
            }
        }
        // uint256 p = Bn254Crypto.r_mod;
        assembly {
            challenge := mod(challenge, PRIME_R)
        }
        return (uint256)(challenge);
    }
}
