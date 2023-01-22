// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract TestMem {
    function testMstore() public pure {
        uint256[7] memory inputs;
        inputs[0] = 0;
        inputs[1] = 1;
        inputs[2] = 2;
        inputs[3] = 3;

        assembly {
            mstore(inputs, 9)
            mstore(add(inputs, 0x20), 8)
            mstore(add(inputs, 0x40), 7)
        }
    }

    function new_transcript()
        public
        pure
    {
        bytes memory transcript_data_pointer;
        assembly {
            transcript_data_pointer := mload(0x40)
            mstore(0x40, add(transcript_data_pointer, 1248))
        }

        // ,,...
        // bytes memory val;;
        // assembly {
        //     // ptr2 := mload(0x40) // 560 
        //     mstore(add(0x40, 0x20), add(transcript_data_pointer, 1248))
        // }

    }
}
