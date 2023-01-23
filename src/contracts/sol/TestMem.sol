// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import "forge-std/console2.sol";

contract TestMem {
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
