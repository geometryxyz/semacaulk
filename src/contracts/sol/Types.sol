// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Types {
    struct G1Point {
        uint256 x;
        uint256 y;
    }
    // G2 group element where x \in Fq2 = x0 * z + x1
    struct G2Point {
        uint256 x0;
        uint256 x1;
        uint256 y0;
        uint256 y1;
    }

    struct ChallengeTranscript {
        /* 0x00 */ uint256 v;
        /* 0x20 */ uint256 hi_2;
        /* 0x40 */ uint256 alpha;
        /* 0x60 */ uint256 x1; 
        /* 0x80 */ uint256 x2; 
        /* 0xa0 */ uint256 x3; 
        /* 0xc0 */ uint256 x4; 
        /* 0xe0 */ uint256 s; 
    }

    struct VerifierTranscript {
        /* 0x00  */ uint256 d;
        /* 0x20  */ uint256 omega_alpha;
        /* 0x40  */ uint256 omega_n_alpha;
        /* 0x60  */ uint256 dMinusOneInv;
        /* 0x80  */ uint256 xi_minus_v_inv;
        /* 0xa0  */ uint256 xi_minus_alpha_inv;
        /* 0xc0  */ uint256 xi_minus_omega_alpha_inv;
        /* 0xe0  */ uint256 xi_minus_omega_n_alpha_inv;
        /* 0x100 */ uint256 alpha_minus_omega_alpha_inv;
        /* 0x120 */ uint256 alpha_minus_omega_n_alpha_inv;
        /* 0x140 */ uint256 omega_alpha_minus_omega_n_alpha_inv;
        /* 0x160 */ uint256 l0Eval;
        /* 0x180 */ uint256 zhEval;
        /* 0x1a0 */ uint256 x1_pow_2;
        /* 0x1c0 */ uint256 x1_pow_3;
        /* 0x1e0 */ uint256 x1_pow_4;
        /* 0x200 */ uint256 x2_pow_2;
        /* 0x220 */ uint256 x2_pow_3;
        /* 0x240 */ uint256 x4_pow_2;
        /* 0x260 */ uint256 x4_pow_3;
        /* 0x280 */ uint256 x4_pow_4;
        /* 0x2a0 */ Types.G1Point q2;
        /* 0x2c0 */ Types.G1Point q4;
        /* 0x2e0 */ uint256 q4_at_alpha;
        /* 0x300 */ uint256 q4_at_omega_alpha;
        /* 0x320 */ uint256 q4_at_omega_n_alpha;
        /* 0x340 */ uint256 q2_eval;
        /* 0x360 */ uint256 f1;
        /* 0x380 */ uint256 f2;
        /* 0x3a0 */ uint256 f3;
        /* 0x3c0 */ uint256 f4;
        /* 0x3e0 */ uint256 xi_minus_omega_alpha;
        /* 0x400 */ uint256 xi_minus_alpha;
        /* 0x420 */ uint256 xi_minus_omega_n_alpha;
        /* 0x440 */ uint256 omega_alpha_minus_alpha_inv;
        /* 0x460 */ uint256 z3_xi;
        /* 0x480 */ uint256 f_eval;
        /* 0x4a0 */ Types.G1Point final_poly;
    }

    struct Commitments {
        /* 0x00  */ Types.G1Point w0;
        /* 0x40  */ Types.G1Point w1;
        /* 0x80  */ Types.G1Point w2;
        /* 0xc0  */ Types.G1Point key;
        /* 0x100 */ Types.G1Point c;
        /* 0x140 */ Types.G1Point quotient;
        /* 0x180 */ Types.G1Point u_prime;
        /* 0x1c0 */ Types.G1Point zi;
        /* 0x200 */ Types.G1Point ci;
        /* 0x240 */ Types.G1Point p1;
        /* 0x280 */ Types.G1Point p2;
        /* 0x2c0 */ Types.G1Point q_mimc;
        /* 0x300 */ Types.G1Point h;
        /* 0x340 */ Types.G2Point w;
    }

    struct Openings {
        /* 0x00  */ uint256 q_mimc;
        /* 0x20  */ uint256 c;
        /* 0x40  */ uint256 quotient;
        /* 0x60  */ uint256 u_prime;
        /* 0x80  */ uint256 p1;
        /* 0xa0  */ uint256 p2;
        /* 0xc0  */ uint256 w0_0;
        /* 0xe0  */ uint256 w0_1;
        /* 0x100 */ uint256 w0_2;
        /* 0x120 */ uint256 w1_0;
        /* 0x140 */ uint256 w1_1;
        /* 0x160 */ uint256 w1_2;
        /* 0x180 */ uint256 w2_0;
        /* 0x1a0 */ uint256 w2_1;
        /* 0x1c0 */ uint256 w2_2;
        /* 0x1e0 */ uint256 key_0;
        /* 0x200 */ uint256 key_1;
    }

    struct MultiopenProof {
        /* 0x00  */ uint256 q1_opening;
        /* 0x20  */ uint256 q2_opening;
        /* 0x40  */ uint256 q3_opening;
        /* 0x60  */ uint256 q4_opening;
        /* 0x80  */ Types.G1Point f_cm;
        /* 0xa0  */ Types.G1Point final_poly_proof;
    }

    struct Proof {
        /* 0x00 */ MultiopenProof multiopenProof;
        /* 0x20 */ Openings openings;
        /* 0x40 */ Commitments commitments;
    }
}
