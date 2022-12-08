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
        bytes32 current_challenge;
        uint32 challenge_counter;
        // uint256 num_public_inputs;
    } 

    /**
     * Instantiate a transcript and calculate the initial challenge, from which other challenges are derived.
     *
     * Resembles the preamble round in the Plonk prover
     */
    function new_transcript()
        internal
        pure
        returns (Transcript memory transcript)
    {
        transcript.current_challenge = compute_initial_challenge();
        transcript.challenge_counter = 0;
        // manually format the transcript.data bytes array
        // This is because we want to reserve memory that is greatly in excess of the array's initial size
        bytes memory transcript_data_pointer;
        bytes32 transcript_data = transcript.current_challenge;
        uint256 total_transcript_bytes = NUM_TRANSCRIPT_BYTES;
        assembly {
            transcript_data_pointer := mload(0x40)
            mstore(0x40, add(transcript_data_pointer, total_transcript_bytes))
            // update length of transcript.data
            mstore(transcript_data_pointer, 0x20)
            // insert current challenge
            mstore(add(transcript_data_pointer, 0x20), transcript_data)
        }
        transcript.data = transcript_data_pointer;
        // transcript.num_public_inputs = num_public_inputs;
    }

    function compute_initial_challenge() internal pure returns (bytes32 challenge) {
        uint256 x = 0;
        return bytes32(x);
    }

    function update_with_u256(Transcript memory self, uint256 value) internal pure {
        bytes memory data_ptr = self.data;
        assembly {
            // update length of transcript data
            let array_length := mload(data_ptr)
            mstore(data_ptr, add(0x20, array_length))
            // insert new 32-byte value at the end of the array
            mstore(add(data_ptr, add(array_length, 0x20)), value)
        }
    }

    function update_with_g1(Transcript memory self, Types.G1Point memory p) internal pure {
        bytes memory data_ptr = self.data;
        assembly {
            // update length of transcript data
            let array_length := mload(data_ptr)
            mstore(data_ptr, add(0x40, array_length))
            // insert new 64-byte value at the end of the array
            mstore(add(data_ptr, add(array_length, 0x20)), mload(p)) // x cord
            mstore(add(data_ptr, add(array_length, 0x40)), mload(add(p, 0x20))) // y cord
        }
    }

    function reset_to_bytes32(Transcript memory self, bytes32 value) internal pure {
        bytes memory data_ptr = self.data;
        {
            assembly {
                mstore(data_ptr, 0x20)
                mstore(add(data_ptr, 0x20), value)
            }
        }
    }

    function get_challenge(Transcript memory self) internal pure returns (uint256) {
        bytes32 challenge;
        bytes memory data_ptr = self.data;
        assembly {
            let length := mload(data_ptr)
            challenge := keccak256(add(data_ptr, 0x20), length)
        }
        self.current_challenge = challenge;
        // reset self.data by setting length to 0x20 and update first element
        {
            assembly {
                mstore(data_ptr, 0x20)
                mstore(add(data_ptr, 0x20), challenge)
            }
        }
        // uint256 p = Bn254Crypto.r_mod;
        assembly {
            challenge := mod(challenge, PRIME_R)
        }
        return (uint256)(challenge);
    }
}