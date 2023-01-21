// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import { Lagrange } from "../Lagrange.sol";

contract TestLagrange {
    function testComputeL0EvalForge() public view {
        testComputeL0Eval(123);
    }

    function testComputeL0Eval(
        uint256 alpha
    ) public view returns(uint256) {
        return Lagrange.computeL0Eval(alpha);
    }
}
