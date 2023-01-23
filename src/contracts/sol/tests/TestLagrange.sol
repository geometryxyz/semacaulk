// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { Lagrange } from "../Lagrange.sol";

contract TestLagrange {
    function testComputeL0EvalForge() public view {
        testComputeL0Eval(
            0x0CF0C6C9F1F40C61C63021CC7ECEB99F17CE53C3AA263480879D4B927743E508,
            0x1168561103DEB168F701D0FBD0FB769FB5FDE2FD01E56BB4AF633391633FFB34
        );
    }

    function testComputeL0Eval(
        uint256 alpha,
        uint256 dMinusOneInv
    ) public view returns(uint256) {
        (uint256 result, uint256 zhEval) = Lagrange.computeL0AndVanishingEval(alpha, dMinusOneInv);
        console2.log(result);
        console2.log(zhEval);
        return result;
    }
}
