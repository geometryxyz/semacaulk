// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Types {
    uint256 constant PROGRAM_WIDTH = 4;
    uint256 constant NUM_NU_CHALLENGES = 11;
    uint256 constant coset_generator0 = 0x0000000000000000000000000000000000000000000000000000000000000005;
    uint256 constant coset_generator1 = 0x0000000000000000000000000000000000000000000000000000000000000006;
    uint256 constant coset_generator2 = 0x0000000000000000000000000000000000000000000000000000000000000007;
    // TODO: add external_coset_generator() method to compute this
    uint256 constant coset_generator7 = 0x000000000000000000000000000000000000000000000000000000000000000c;

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
    }

    struct VerifierTranscript {
        uint256 d;
        uint256 omega_alpha;
        uint256 omega_n_alpha;
    }

    struct Commitments {
        Types.G1Point w0;
        Types.G1Point w1;
        Types.G1Point w2;
        Types.G1Point key;
        Types.G1Point c;
        Types.G1Point quotient;
        Types.G1Point u_prime;
        Types.G1Point zi;
        Types.G1Point ci;
        Types.G1Point p1;
        Types.G1Point p2;
        Types.G1Point q_mimc;
        Types.G1Point h;
        Types.G2Point w;
    }

    struct Openings {
        uint256 q_mimc;
        uint256 c;
        uint256 quotient;
        uint256 u_prime;
        uint256 p1;
        uint256 p2;
        uint256 w0_0;
        uint256 w0_1;
        uint256 w0_2;
        uint256 w1_0;
        uint256 w1_1;
        uint256 w1_2;
        uint256 w2_0;
        uint256 w2_1;
        uint256 w2_2;
        uint256 key_0;
        uint256 key_1;
    }

    struct MultiopenProof {
        uint256 q1_opening;
        uint256 q2_opening;
        uint256 q3_opening;
        uint256 q4_opening;
        Types.G1Point f_cm;
        Types.G1Point final_poly_proof;
    }

    struct Proof {
        MultiopenProof multiopenProof;
        Openings openings;
        Commitments commitments;
    }
}
