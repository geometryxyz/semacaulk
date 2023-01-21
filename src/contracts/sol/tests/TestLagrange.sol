// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Lagrange } from "../Lagrange.sol";

contract TestLagrange {
    function testComputeL0Eval(
        uint256 alpha
    ) public view returns(uint256) {
        return Lagrange.computeL0Eval(alpha);
    }
}
