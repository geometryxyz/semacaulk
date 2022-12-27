// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Semacaulk } from "./Semacaulk.sol";
import "forge-std/Test.sol";

contract TestSemacaulk is Test {
    Semacaulk public semacaulk;
    constructor(
    ) {
        semacaulk = new Semacaulk(bytes32(uint256(1)), 2, 3);
    }

    function testIdNullifierGateEval() public {
        semacaulk.idNullifierGateEval(1, 2, 3, 4);
    }

    function testIdCommLrdEval() public {
        semacaulk.idCommLrdEval(1, 2, 3, 4, 5);
    }

    function testKeyConstantEval() public {
        semacaulk.keyConstantEval(1, 2, 3);
    }

    function testKeyCopyEval() public {
        semacaulk.keyCopyEval(1, 2, 3, 4);
    }

    function testNullifierHashFinalEval() public {
        semacaulk.nullifierHashFinalEval(1, 2, 3, 4, 5);
    }
}
