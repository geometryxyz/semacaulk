// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";
import { TranscriptLibrary } from "./Transcript.sol";
import { Lagrange } from "./Lagrange.sol";
import { BN254 } from "./BN254.sol";

contract Verifier is BN254 {
    function verify(
        Types.Proof memory proof,
        Types.G1Point memory accumulator,
        uint256[3] memory publicInputs
    ) public view returns (bool) {
        uint256 p = Constants.PRIME_R;

        require(publicInputs[0] < Constants.PRIME_R); // externalNullifier
        require(publicInputs[1] < Constants.PRIME_R); // nullifierHash
        require(publicInputs[2] < Constants.PRIME_R); // signalHash
        
        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary.newTranscript();
        Types.ChallengeTranscript memory challengeTranscript;
        Types.VerifierTranscript memory verifierTranscript;

        TranscriptLibrary.updateWithU256(transcript, publicInputs[0]);
        TranscriptLibrary.updateWithU256(transcript, publicInputs[1]);
        TranscriptLibrary.updateWithU256(transcript, publicInputs[2]);

        TranscriptLibrary.updateWithG1(transcript, proof.commitments.w0);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.key);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.w1);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.w2);

        challengeTranscript.v = TranscriptLibrary.getChallenge(transcript);

        TranscriptLibrary.updateWithG1(transcript, proof.commitments.quotient);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.zi);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.ci);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.u_prime);

        TranscriptLibrary.getChallenge(transcript);
        challengeTranscript.hi_2 = TranscriptLibrary.getChallenge(transcript);

        TranscriptLibrary.updateWithG2(transcript, proof.commitments.w);
        TranscriptLibrary.updateWithG1(transcript, proof.commitments.h);

        challengeTranscript.alpha = TranscriptLibrary.getChallenge(transcript);

        TranscriptLibrary.updateWithU256(transcript, proof.openings.w0_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w0_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w0_2);

        TranscriptLibrary.updateWithU256(transcript, proof.openings.w1_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w1_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w1_2);

        TranscriptLibrary.updateWithU256(transcript, proof.openings.w2_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w2_1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.w2_2);

        TranscriptLibrary.updateWithU256(transcript, proof.openings.key_0);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.key_1);

        TranscriptLibrary.updateWithU256(transcript, proof.openings.q_mimc);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.c);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.quotient);

        TranscriptLibrary.updateWithU256(transcript, proof.openings.u_prime);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.p1);
        TranscriptLibrary.updateWithU256(transcript, proof.openings.p2);

        challengeTranscript.x1 = TranscriptLibrary.getChallenge(transcript);
        challengeTranscript.x2 = TranscriptLibrary.getChallenge(transcript);

        TranscriptLibrary.updateWithG1(transcript, proof.multiopenProof.f_cm);

        challengeTranscript.x3 = TranscriptLibrary.getChallenge(transcript);
        challengeTranscript.x4 = TranscriptLibrary.getChallenge(transcript);
        challengeTranscript.s = TranscriptLibrary.getChallenge(transcript);
        uint256[8] memory inverted;
        
        {
         // Values needed before batch inversion:
         // - d (so we can invert d - 1)
         // - x3_challenge
         // - proof.openings.u_prime_opening
         // - alpha_challenge
         // - omega_alpha
         // - omega_n_alpha

         // Values to invert:
         // - (d - 1) for the l0_eval computation
         // - xi_minus_v = x3_challenge - proof.openings.u_prime_opening
         // - xi_minus_alpha = x3_challenge - alpha_challenge
         // - xi_minus_omega_alpha = x3_challenge - omega_alpha;
         // - xi_minus_omega_n_alpha = x3_challenge - omega_n_alpha
         // - alpha_minus_omega_alpha = alpha - omega_alpha;
         // - alpha_minus_omega_n_alpha = alpha - omega_n_alpha;
         // - omega_alpha_minus_omega_n_alpha = omega_alpha - omega_n_alpha;

        // Compute and store omega_alpha, omega_n_alpha
        uint256 omega_alpha = Constants.OMEGA;
        uint256 omega_n_alpha = Constants.OMEGA_N;
        assembly {
            let alpha := mload(add(challengeTranscript, 0x40))
            omega_alpha := mulmod(omega_alpha, alpha, p)
            omega_n_alpha := mulmod(omega_n_alpha, alpha, p)
        }

        // Compute and store d - 1
        if (challengeTranscript.alpha == 0) {
            inverted[0] = p - 1;
        } else {
            inverted[0] = challengeTranscript.alpha - 1;
        }

        // Compute inputs to the batch inversion function
        assembly {
            let alpha := mload(add(challengeTranscript, 0x40))
            let x3 := mload(add(challengeTranscript, 0xa0))
            let v := mload(add(proof, 0xa0))
            let u_prime_opening := mload(add(mload(add(proof, 0x20)), 0x60))
            let xi_minus_v := addmod(x3, sub(p, u_prime_opening), p)
            let xi_minus_alpha := addmod(x3, sub(p, alpha), p)
            let xi_minus_omega_alpha := addmod(x3, sub(p, omega_alpha), p)
            let xi_minus_omega_n_alpha := addmod(x3, sub(p, omega_n_alpha), p)
            let alpha_minus_omega_alpha := addmod(alpha, sub(p, omega_alpha), p)
            let alpha_minus_omega_n_alpha := addmod(alpha, sub(p, omega_n_alpha), p)
            let omega_alpha_minus_omega_n_alpha := addmod(omega_alpha, sub(p, omega_n_alpha), p)
            // Store values used to evaluate f3 and f4 in verifierTranscript
            mstore(add(verifierTranscript, 0x3e0), xi_minus_omega_alpha)
            mstore(add(verifierTranscript, 0x400), xi_minus_alpha)
            mstore(add(verifierTranscript, 0x420), xi_minus_omega_n_alpha)
            /* 0    (d - 1) is already stored */
            /* 1 */ mstore(add(inverted, 0x20), xi_minus_v)
            /* 2 */ mstore(add(inverted, 0x40), xi_minus_alpha)
            /* 3 */ mstore(add(inverted, 0x60), xi_minus_omega_alpha)
            /* 4 */ mstore(add(inverted, 0x80), xi_minus_omega_n_alpha)
            /* 5 */ mstore(add(inverted, 0xa0), alpha_minus_omega_alpha)
            /* 6 */ mstore(add(inverted, 0xc0), alpha_minus_omega_n_alpha)
            /* 7 */ mstore(add(inverted, 0xe0), omega_alpha_minus_omega_n_alpha)
        }
        }

        {
        inverted = batchInvert(inverted);

        (uint256 l0Eval, uint256 zhEval) = Lagrange.computeL0AndVanishingEval(
            challengeTranscript.alpha,
            inverted[0],
            Constants.LOG2_DOMAIN_SIZE,
            Constants.DOMAIN_SIZE_INV
        );

        assembly {
            // Store the inverted values to verifierTranscript. They will be
            // used in the multiopen veriifer step
            mstore(add(verifierTranscript, 0x60), mload(inverted))
            mstore(add(verifierTranscript, 0x80), mload(add(inverted, 0x20)))
            mstore(add(verifierTranscript, 0xa0), mload(add(inverted, 0x40)))
            mstore(add(verifierTranscript, 0xc0), mload(add(inverted, 0x60)))
            mstore(add(verifierTranscript, 0xe0), mload(add(inverted, 0x80)))
            mstore(add(verifierTranscript, 0x100), mload(add(inverted, 0xa0)))
            mstore(add(verifierTranscript, 0x120), mload(add(inverted, 0xc0)))
            mstore(add(verifierTranscript, 0x140), mload(add(inverted, 0xe0)))

            // Store l0Eval, zhEval in verifierTranscript. They will be used in
            // verifyGateEvals()
            mstore(add(verifierTranscript, 0x160), l0Eval)
            mstore(add(verifierTranscript, 0x180), zhEval)
        }

        require(
            verifyGateEvals(
                proof,
                verifierTranscript,
                challengeTranscript.v,
                publicInputs
            ),
            "Verifier: gate check failed"
        );
        }

        // Multiopen proof verification
        computeMultiopenFinaPolyAndEval(
            proof,
            verifierTranscript,
            challengeTranscript
        );

        return verifyFinal(
            proof,
            verifierTranscript,
            challengeTranscript,
            accumulator
        );
    }

    function verifyFinal(
        Types.Proof memory proof,
        Types.VerifierTranscript memory verifierTranscript,
        Types.ChallengeTranscript memory challengeTranscript,
        Types.G1Point memory accumulator
    ) internal view returns (bool) {
        // Compute a_lhs = a1 + a2 + a3
        // let a1 = accumulator + proof.commitments.ci.neg();
        Types.G1Point memory a1 = plus(accumulator, negate(proof.commitments.ci));

        // let a2 = (a2_srs_g1 + g1_gen.neg()).mul(hi_2).into_affine();
        Types.G1Point memory a2 = mul(
            plus(
                Types.G1Point(Constants.SRS_G1_T_X, Constants.SRS_G1_T_Y),
                BN254.P1Neg()
            ),
            challengeTranscript.hi_2
        );

        // let a3 = (zq + minus_y).add_mixed(&final_poly).into_affine().mul(s).into_affine();
        Types.G1Point memory a3 = mul(
            plus(
                plus(
                    mul(proof.multiopenProof.final_poly_proof, challengeTranscript.x3), 
                    negate(mul(BN254.P1(), verifierTranscript.final_poly_eval))
                ), 
                verifierTranscript.final_poly
            ), 
            challengeTranscript.s
        );

        Types.G1Point memory a_lhs = plus(plus(a1, a2), a3);
        Types.G2Point memory a_rhs = BN254.P2();

        // let b_lhs = proof.commitments.zi.neg();
        Types.G1Point memory b_lhs = negate(proof.commitments.zi);
        Types.G2Point memory b_rhs = proof.commitments.w;

        // let c_lhs = final_poly_proof.neg().mul(s).into_affine();
        Types.G1Point memory c_lhs = mul(negate(proof.multiopenProof.final_poly_proof), challengeTranscript.s);
        Types.G2Point memory c_rhs = Types.G2Point(
            Constants.SRS_G2_1_X_0,
            Constants.SRS_G2_1_X_1,
            Constants.SRS_G2_1_Y_0,
            Constants.SRS_G2_1_Y_1
        );

        // TODO: check that all points are valid!
        return BN254.pairingCheck(
            a_lhs, a_rhs,
            b_lhs, b_rhs,
            c_lhs, c_rhs
        );
    }

    function computeMultiopenFinaPolyAndEval(
        Types.Proof memory proof,
        Types.VerifierTranscript memory verifierTranscript,
        Types.ChallengeTranscript memory challengeTranscript
    ) internal view {
        uint256 p = Constants.PRIME_R;
        bool success;
        assembly {

            let x1 := mload(add(challengeTranscript, 0x60))
            let x2 := mload(add(challengeTranscript, 0x80))
            let x4 := mload(add(challengeTranscript, 0xc0))

            // Compute and store x1 powers
            let x1_pow_2 := mulmod(x1, x1, p)
            let x1_pow_3 := mulmod(x1_pow_2, x1, p)
            let x1_pow_4 := mulmod(x1_pow_3, x1, p)
            mstore(add(verifierTranscript, 0x1a0), x1_pow_2)
            mstore(add(verifierTranscript, 0x1c0), x1_pow_3)
            mstore(add(verifierTranscript, 0x1e0), x1_pow_4)

            // Compute and store x2 powers
            let x2_pow_2 := mulmod(x2, x2, p)
            let x2_pow_3 := mulmod(x2_pow_2, x2, p)
            mstore(add(verifierTranscript, 0x200), x2_pow_2)
            mstore(add(verifierTranscript, 0x220), x2_pow_3)

            // Compute and store x4 powers
            let x4_pow_2 := mulmod(x4, x4, p)
            let x4_pow_3 := mulmod(x4_pow_2, x4, p)
            let x4_pow_4 := mulmod(x4_pow_3, x4, p)
            mstore(add(verifierTranscript, 0x240), x4_pow_2)
            mstore(add(verifierTranscript, 0x260), x4_pow_3)
            mstore(add(verifierTranscript, 0x280), x4_pow_4)

            let commitmentsPtr := mload(add(proof, 0x40))
            {
            let q_x
            let q_y
            // Compute q2 = q_mimc + (x1 * c) + (x1_pow_2 * quotient) + (x1_pow_3 + u_prime) + (x1_pow_4 + p2)
            let mPtr := mload(0x40)

            // Compute x1 * c and store the result in the stack
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x100)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0x120)))
            mstore(add(mPtr, 0x40), x1)
            success := staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40)

            let x1_mul_c_x := mload(0x00)
            let x1_mul_c_y := mload(0x20)

            // Compute x1_pow_2 * quotient
            // and store the result in scratch space
            mPtr := mload(0x40)
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x140)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0x160)))
            mstore(add(mPtr, 0x40), x1_pow_2)
            success := and(success, staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40))

            // Compute (x1 * c) + (x1_pow_2 * quotient)
            // and store the result in the stack
            mPtr := mload(0x40)
            mstore(mPtr, x1_mul_c_x)
            mstore(add(mPtr, 0x20), x1_mul_c_y)
            mstore(add(mPtr, 0x40), mload(0x00))
            mstore(add(mPtr, 0x60), mload(0x20))
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))
            q_x := mload(0x00)
            q_y := mload(0x20)

            // Compute x1_pow_3 * u_prime
            // and store the result in scratch space
            mPtr := mload(0x40)
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x180)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0x1a0)))
            mstore(add(mPtr, 0x40), x1_pow_3)
            success := and(success, staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40))

            // Compute (x1 * c) + (x1_pow_2 * quotient) + (x1_pow_3 * u_prime)
            // and store the result in the stack
            mPtr := mload(0x40)
            mstore(mPtr, q_x)
            mstore(add(mPtr, 0x20), q_y)
            mstore(add(mPtr, 0x40), mload(0x00))
            mstore(add(mPtr, 0x60), mload(0x20))
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))
            q_x := mload(0x00)
            q_y := mload(0x20)

            // Compute x1_pow_4 * p2 and store the result in scratch space
            mPtr := mload(0x40)
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x280)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0x2a0)))
            mstore(add(mPtr, 0x40), x1_pow_4)
            success := and(success, staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40))

            // Compute (x1 * c) + (x1_pow_2 * quotient) + (x1_pow_3 * u_prime) + (x1_pow_4 * p2)
            // and store the result in the stack
            mPtr := mload(0x40)
            mstore(mPtr, q_x)
            mstore(add(mPtr, 0x20), q_y)
            mstore(add(mPtr, 0x40), mload(0x00))
            mstore(add(mPtr, 0x60), mload(0x20))
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))
            q_x := mload(0x00)
            q_y := mload(0x20)

            // Compute q_mimc + (x1 * c) + (x1_pow_2 * quotient) + (x1_pow_3 * u_prime) + (x1_pow_4 * p2)
            // and store the result in verifierTranscript
            mPtr := mload(0x40)
            mstore(mPtr, q_x)
            mstore(add(mPtr, 0x20), q_y)
            mstore(add(mPtr, 0x40), mload(add(mload(commitmentsPtr), 0x2c0)))
            mstore(add(mPtr, 0x60), mload(add(mload(commitmentsPtr), 0x2e0)))
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))

            mstore(mload(add(verifierTranscript, 0x2a0)), mload(0x00))
            mstore(add(mload(add(verifierTranscript, 0x2a0)), 0x20), mload(0x20))
            }

            {
            // Compute q2_eval = q_mimc_opening
            //  + c_opening * x1
            //  + quotient_opening * x1_pow_2
            //  + u_prime_opening * x1_pow_3
            //  + p2_opening * x1_pow_4
            let q_x
            let q_y
            let openingsPtr := mload(add(proof, 0x20))
            let c := mload(add(openingsPtr, 0x20))
            let quotient := mload(add(openingsPtr, 0x40))
            let u_prime := mload(add(openingsPtr, 0x60))
            let p2 := mload(add(openingsPtr, 0xa0))
            
            let q2_eval := mulmod(c, x1, p)
            q2_eval := addmod(q2_eval, mulmod(x1_pow_2, quotient, p), p)
            q2_eval := addmod(q2_eval, mulmod(x1_pow_3, u_prime, p), p)
            q2_eval := addmod(q2_eval, mulmod(x1_pow_4, p2, p), p)
            q2_eval := addmod(q2_eval, mload(openingsPtr), p) // q_mimc
            mstore(add(verifierTranscript, 0x340), q2_eval)
            }

            {
            // Compute q4 = (x1 * w1) + (x1_pow_2 * w2) + w0

            // Compute x1 * w1
            // and store the result in scratch space
            let q_x
            let q_y
            let mPtr := mload(0x40)
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x40)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0x60)))
            mstore(add(mPtr, 0x40), x1)
            success := and(success, staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40))
            q_x := mload(0x00)
            q_y := mload(0x20)

            // Compute (x1 * w1) + (x1_pow_2 * w2)
            // and store the result in scratch space
            mPtr := mload(0x40)
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x80)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0xa0)))
            mstore(add(mPtr, 0x40), x1_pow_2)
            success := and(success, staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40))

            mPtr := mload(0x40)
            mstore(mPtr, q_x)
            mstore(add(mPtr, 0x20), q_y)
            mstore(add(mPtr, 0x40), mload(0x00))
            mstore(add(mPtr, 0x60), mload(0x20))
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))

            // Compute (x1 * w1) + (x1_pow_2 * w2) + w0
            mPtr := mload(0x40)
            mstore(mPtr, mload(0x00))
            mstore(add(mPtr, 0x20), mload(0x20))
            mstore(add(mPtr, 0x40), mload(    mload(commitmentsPtr)       ))
            mstore(add(mPtr, 0x60), mload(add(mload(commitmentsPtr), 0x20)))
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))

            mstore(mload(add(verifierTranscript, 0x2c0)), mload(0x00))
            mstore(add(mload(add(verifierTranscript, 0x2c0)), 0x20), mload(0x20))
            }

            {
            // Compute q4 evals
            //let q4_at_alpha = compute_q4_eval(w0_openings[0], w1_openings[0], w2_openings[0], &x1_powers);
            //let q4_at_omega_alpha = compute_q4_eval(w0_openings[1], w1_openings[1], w2_openings[1], &x1_powers);
            //let q4_at_omega_n_alpha = compute_q4_eval(w0_openings[2], w1_openings[2], w2_openings[2], &x1_powers);

            let openingsPtr := mload(add(proof, 0x20))

            function compute_q4_eval(w0, w1, w2, x1_f, x1_pow_2_f, prime) -> result {
                // w0_opening + (x1_powers[0] * w1_opening) + (x1_powers[1] * w2_opening)
                // x1_f and x1_pow_2_f are named as such to avoid a name collision
                let a := mulmod(w1, x1_f, prime)
                let b := mulmod(w2, x1_pow_2_f, prime)
                let ab := addmod(a, b, prime)
                result := addmod(w0, ab, prime)
            }

            let w0_0 := mload(add(openingsPtr, 0xc0))
            let w1_0 := mload(add(openingsPtr, 0x120))
            let w2_0 := mload(add(openingsPtr, 0x180))
            let q4_at_alpha := compute_q4_eval(w0_0, w1_0, w2_0, x1, x1_pow_2, p)
            mstore(add(verifierTranscript, 0x2e0), q4_at_alpha)

            let w0_1 := mload(add(openingsPtr, 0xe0))
            let w1_1 := mload(add(openingsPtr, 0x140))
            let w2_1 := mload(add(openingsPtr, 0x1a0))
            let q4_at_omega_alpha := compute_q4_eval(w0_1, w1_1, w2_1, x1, x1_pow_2, p)
            mstore(add(verifierTranscript, 0x300), q4_at_omega_alpha)

            let w0_2 := mload(add(openingsPtr, 0x100))
            let w1_2 := mload(add(openingsPtr, 0x160))
            let w2_2 := mload(add(openingsPtr, 0x1c0))
            let q4_at_omega_n_alpha := compute_q4_eval(w0_2, w1_2, w2_2, x1, x1_pow_2, p)
            mstore(add(verifierTranscript, 0x320), q4_at_omega_n_alpha)
            }

            // Compute fs (f1, f2, f3, f4)
            {
            let openingsPtr := mload(add(proof, 0x20))
            let multiopenProofPtr := mload(proof)

            // Compute f1 = (multiopenProof.q1_opening - p1_opening) * xi_minus_v_inv
            // and store it in verifierTranscript
            let q1 := mload(multiopenProofPtr)
            let p1 := mload(add(openingsPtr, 0x80))
            let xi_minus_v_inv := mload(add(verifierTranscript, 0x80))

            let f1 := mulmod(
                addmod(q1, sub(p, p1), p),
                xi_minus_v_inv,
                p
            )
            mstore(add(verifierTranscript, 0x360), f1)

            // Compute f2 = (multiopenProof.q2_opening - q2_eval) * xi_minus_alpha_inv
            let q2 := mload(add(multiopenProofPtr, 0x20))
            let q2_eval := mload(add(verifierTranscript, 0x340))
            let xi_minus_alpha_inv := mload(add(verifierTranscript, 0xa0))
            let f2 := mulmod(
                addmod(q2, sub(p, q2_eval), p),
                xi_minus_alpha_inv,
                p
            )
            mstore(add(verifierTranscript, 0x380), f2)
            }

            {
            let openingsPtr := mload(add(proof, 0x20))
            let multiopenProofPtr := mload(proof)
            // Compute f3 = (multiopenProof.q3_opening - r3_xi) * 
            //              (xi_minus_alpha_inv * xi_minus_omega_alpha_inv)
            let q3 := mload(add(multiopenProofPtr, 0x40))
            let xi_minus_alpha_inv := mload(add(verifierTranscript, 0xa0))
            let xi_minus_omega_alpha_inv := mload(add(verifierTranscript, 0xc0))

            // Compute l_1_3 = xi_minus_omega_alpha * alpha_minus_omega_alpha_inv;
            let xi_minus_omega_alpha := mload(add(verifierTranscript, 0x3e0))
            let alpha_minus_omega_alpha_inv := mload(add(verifierTranscript, 0x100))
            let l_1_3 := mulmod(xi_minus_omega_alpha, alpha_minus_omega_alpha_inv, p)

            // Compute l_2_3 = xi_minus_alpha * omega_alpha_minus_alpha_inv;
            let xi_minus_alpha := mload(add(verifierTranscript, 0x400))
            let omega_alpha_minus_alpha_inv := sub(p, alpha_minus_omega_alpha_inv)
            let l_2_3 := mulmod(xi_minus_alpha, omega_alpha_minus_alpha_inv, p)

            // Store omega_alpha_minus_alpha_inv
            mstore(add(verifierTranscript, 0x440), omega_alpha_minus_alpha_inv)

            // Compute r3_xi = key_openings[0] * l_1_3 + key_openings[1] * l_2_3;
            let key_0 := mload(add(openingsPtr, 0x1e0))
            let key_1 := mload(add(openingsPtr, 0x200))
            let r3_xi := addmod(
                mulmod(key_0, l_1_3, p),
                mulmod(key_1, l_2_3, p),
                p
            )

            // Compute z3_xi and store it in verifierTranscript
            let z3_xi := mulmod(xi_minus_alpha_inv, xi_minus_omega_alpha_inv, p)
            mstore(add(verifierTranscript, 0x460), z3_xi)

            let f3 := mulmod(
                addmod(q3, sub(p, r3_xi), p),
                z3_xi,
                p
            )
            mstore(add(verifierTranscript, 0x3a0), f3)
            }

            {
            let openingsPtr := mload(add(proof, 0x20))
            let multiopenProofPtr := mload(proof)
            // Compute f4 = (multiopenProof.q4_opening - r4_xi) * z4_xi;

            // Compute l_1_4 = xi_minus_omega_alpha
                //* xi_minus_omega_n_alpha
                //* alpha_minus_omega_alpha_inv
                //* alpha_minus_omega_n_alpha_inv;
            let xi_minus_omega_alpha := mload(add(verifierTranscript, 0x3e0))
            let xi_minus_omega_n_alpha := mload(add(verifierTranscript, 0x420))
            let alpha_minus_omega_alpha_inv := mload(add(verifierTranscript, 0x100))
            let alpha_minus_omega_n_alpha_inv := mload(add(verifierTranscript, 0x120))
            let l_1_4 := mulmod(xi_minus_omega_alpha, xi_minus_omega_n_alpha, p)
            l_1_4 := mulmod(l_1_4, alpha_minus_omega_alpha_inv, p)
            l_1_4 := mulmod(l_1_4, alpha_minus_omega_n_alpha_inv, p)

            // Compute l_2_4 = xi_minus_alpha
                //* xi_minus_omega_n_alpha
                //* omega_alpha_minus_alpha_inv
                //* omega_alpha_minus_omega_n_alpha_inv;
            let xi_minus_alpha := mload(add(verifierTranscript, 0x400))
            let omega_alpha_minus_alpha_inv := mload(add(verifierTranscript, 0x440))
            let omega_alpha_minus_omega_n_alpha_inv := mload(add(verifierTranscript, 0x140))
            let l_2_4 := mulmod(xi_minus_alpha, xi_minus_omega_n_alpha, p)
            l_2_4 := mulmod(l_2_4, omega_alpha_minus_alpha_inv, p)
            l_2_4 := mulmod(l_2_4, omega_alpha_minus_omega_n_alpha_inv, p)

             // Compute l_3_4 = xi_minus_alpha
                //* xi_minus_omega_alpha
                //* omega_n_alpha_minus_alpha_inv
                //* omega_n_alpha_minus_omega_alpha_inv;
                //}
            let omega_n_alpha_minus_alpha_inv := sub(p, mload(add(verifierTranscript, 0x120)))
            let omega_n_alpha_minus_omega_alpha_inv := sub(p, mload(add(verifierTranscript, 0x140)))
            let l_3_4 := mulmod(xi_minus_alpha, xi_minus_omega_alpha, p)
            l_3_4 := mulmod(l_3_4, omega_n_alpha_minus_alpha_inv, p)
            l_3_4 := mulmod(l_3_4, omega_n_alpha_minus_omega_alpha_inv, p)

            // Compute r4_xi = (q4_at_alpha * l_1_4) + 
            //                 (q4_at_omega_alpha * l_2_4) + 
            //                 (q4_at_omega_n_alpha * l_3_4)
            let q4_at_alpha := mload(add(verifierTranscript, 0x2e0))
            let q4_at_omega_alpha := mload(add(verifierTranscript, 0x300))
            let q4_at_omega_n_alpha := mload(add(verifierTranscript, 0x320))
            let r4_xi := mulmod(q4_at_alpha, l_1_4, p)
            r4_xi := addmod(r4_xi, mulmod(q4_at_omega_alpha, l_2_4, p), p)
            r4_xi := addmod(r4_xi, mulmod(q4_at_omega_n_alpha, l_3_4, p), p)

            // Compute z4_xi = z3_xi * xi_minus_omega_n_alpha_inv;
            let z3_xi := mload(add(verifierTranscript, 0x460))
            let xi_minus_omega_n_alpha_inv := mload(add(verifierTranscript, 0xe0))
            let z4_xi := mulmod(z3_xi, xi_minus_omega_n_alpha_inv, p)

            let q3 := mload(add(multiopenProofPtr, 0x60))
            let f4 := mulmod(addmod(q3, sub(p, r4_xi), p), z4_xi, p)
            mstore(add(verifierTranscript, 0x3c0), f4)
            }

            {
            // Compute final_poly = f_cm +
            //                      (p1 * x4) +
            //                      (q2 * x4_pow_2) +
            //                      (key * x4_pow_3) +
            //                      (q4 * x4_pow_4) +
            let x
            let y
            let mPtr := mload(0x40)
            // Compute and store (p1 * x4)
            // in the stack
            mstore(    mPtr,        mload(add(mload(commitmentsPtr), 0x240)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0x260)))
            mstore(add(mPtr, 0x40), mload(add(challengeTranscript, 0xc0)))
            success := staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40)
            x := mload(0x00)
            y := mload(0x20)

            // Compute and store (p1 * x4) + (q2 * x4_pow_2)
            // in the stack
            mPtr := mload(0x40)
            mstore(mPtr, mload(mload(add(verifierTranscript, 0x2a0))))
            mstore(add(mPtr, 0x20), mload(add(mload(add(verifierTranscript, 0x2a0)), 0x20)))
            mstore(add(mPtr, 0x40), mload(add(verifierTranscript, 0x240)))
            success := staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40)

            mPtr := mload(0x40)
            mstore(mPtr, mload(0x00))
            mstore(add(mPtr, 0x20), mload(0x20))
            mstore(add(mPtr, 0x40), x)
            mstore(add(mPtr, 0x60), y)
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))
            x := mload(0x00)
            y := mload(0x20)

            // Compute and store (p1 * x4) + (q2 * x4_pow_2) + (key * x4_pow_3)
            // in the stack
            mPtr := mload(0x40)
            mstore(mPtr, mload(add(mload(commitmentsPtr), 0xc0)))
            mstore(add(mPtr, 0x20), mload(add(mload(commitmentsPtr), 0xe0)))
            mstore(add(mPtr, 0x40), mload(add(verifierTranscript, 0x260)))
            success := staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40)

            mPtr := mload(0x40)
            mstore(mPtr, mload(0x00))
            mstore(add(mPtr, 0x20), mload(0x20))
            mstore(add(mPtr, 0x40), x)
            mstore(add(mPtr, 0x60), y)
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))
            x := mload(0x00)
            y := mload(0x20)

            // Compute and store (p1 * x4) + (q2 * x4_pow_2) + (key * x4_pow_3) + (q4 * x4_pow_4)
            // in the stack
            mPtr := mload(0x40)
            mstore(mPtr, mload(mload(add(verifierTranscript, 0x2c0))))
            mstore(add(mPtr, 0x20), mload(add(mload(add(verifierTranscript, 0x2c0)), 0x20)))
            mstore(add(mPtr, 0x40), mload(add(verifierTranscript, 0x280)))
            success := staticcall(sub(gas(), 2000), 7, mPtr, 0x60, 0x00, 0x40)

            mPtr := mload(0x40)
            mstore(mPtr, mload(0x00))
            mstore(add(mPtr, 0x20), mload(0x20))
            mstore(add(mPtr, 0x40), x)
            mstore(add(mPtr, 0x60), y)
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))
            x := mload(0x00)
            y := mload(0x20)

            // Compute and store (p1 * x4) + (q2 * x4_pow_2) + (key * x4_pow_3) + (q4 * x4_pow_4) + f_cm
            // in verifierTranscript
            let multiopenProofPtr := mload(proof)
            mPtr := mload(0x40)
            mstore(mPtr, mload(mload(add(multiopenProofPtr, 0x80))))
            mstore(add(mPtr, 0x20), mload(add(mload(add(multiopenProofPtr, 0x80)), 0x20)))
            mstore(add(mPtr, 0x40), x)
            mstore(add(mPtr, 0x60), y)
            success := and(success, staticcall(sub(gas(), 2000), 6, mPtr, 0x80, 0x00, 0x40))

            mstore(mload(add(verifierTranscript, 0x4a0)), mload(0x00))
            mstore(add(mload(add(verifierTranscript, 0x4a0)), 0x20), mload(0x20))
            }

            {
            // Compute f_eval = f1 + 
            //                  (x2_powers[0] * f2) + 
            //                  (x2_powers[1] * f3) + 
            //                  (x2_powers[2] * f4)
            let x2_2 := mload(add(verifierTranscript, 0x200))
            let x2_3 := mload(add(verifierTranscript, 0x220))

            let f_eval := mload(add(verifierTranscript, 0x360))
            f_eval := addmod(f_eval, mulmod(mload(add(verifierTranscript, 0x380)), x2, p), p)
            f_eval := addmod(f_eval, mulmod(mload(add(verifierTranscript, 0x3a0)), x2_2, p), p)
            f_eval := addmod(f_eval, mulmod(mload(add(verifierTranscript, 0x3c0)), x2_3, p), p)
            mstore(add(verifierTranscript, 0x480), f_eval)

            // Compute final_poly_eval = f_eval
            //  + proof.q1_opening * x4
            //  + proof.q2_opening * x4_pow_2
            //  + proof.q3_opening * x4_pow_3
            //  + proof.q4_opening * x4_pow_4
            let multiopenProofPtr := mload(proof)
            let final_poly_eval := addmod(
                f_eval,
                mulmod(mload(multiopenProofPtr), mload(add(challengeTranscript, 0xc0)), p),
                p
            )
            final_poly_eval := addmod(
                final_poly_eval,
                mulmod(mload(add(multiopenProofPtr, 0x20)), mload(add(verifierTranscript, 0x240)), p),
                p
            )
            final_poly_eval := addmod(
                final_poly_eval,
                mulmod(mload(add(multiopenProofPtr, 0x40)), mload(add(verifierTranscript, 0x260)), p),
                p
            )
            final_poly_eval := addmod(
                final_poly_eval,
                mulmod(mload(add(multiopenProofPtr, 0x60)), mload(add(verifierTranscript, 0x280)), p),
                p
            )
            mstore(add(verifierTranscript, 0x4c0), final_poly_eval)

            switch success case 0 { revert(0, 0) }
            }
        }
        require(success, "Verifier: failed to compute final poly or eval");
    }

    function verifyGateEvals(
        Types.Proof memory proof,
        Types.VerifierTranscript memory verifierTranscript,
        uint256 v_challenge,
        uint256[3] memory publicInputs
    ) internal pure returns (bool) {
        uint256 p = Constants.PRIME_R;
        uint256 rhs;
        uint256 lhs;

        assembly {
            function pow7(val, prime) -> r {
                let val2 := mulmod(val, val, prime)
                let val4 := mulmod(val2, val2, prime)
                let val6 := mulmod(val2, val4, prime)
                r := mulmod(val6, val, prime)
            }

            let rolling_v := v_challenge
            let openingsPtr := mload(add(proof, 0x20))

            {
            // Compute rhs = zh_eval * quotient_opening
            let zh_eval := mload(add(verifierTranscript, 0x180))
            let quotient_opening := mload(add(openingsPtr, 0x40))
            rhs := mulmod(zh_eval, quotient_opening, p)
            }

            {
            //let gate_0_eval = q_mimc_opening * (pow_7(w0_openings[0] + c_opening) - w0_openings[1]);
            let q_mimc := mload(openingsPtr)
            let c := mload(add(openingsPtr, 0x20))
            let w0_0 := mload(add(openingsPtr, 0xc0))
            let w0_1 := mload(add(openingsPtr, 0xe0))

            let gate_0_eval := addmod(w0_0, c, p)
            gate_0_eval := pow7(gate_0_eval, p)
            gate_0_eval := addmod(gate_0_eval, sub(p, w0_1), p)
            gate_0_eval := mulmod(gate_0_eval, q_mimc, p)
            lhs := gate_0_eval
            }

            {
            let q_mimc := mload(openingsPtr)
            let c := mload(add(openingsPtr, 0x20))
            // Gate 1: q_mimc_opening * ((w1_openings[0] + key_openings[0] + c_opening) ^ 7 - w1_openings[1])
            let w1_0 := mload(add(openingsPtr, 0x120))
            let w1_1 := mload(add(openingsPtr, 0x140))
            let key_0 := mload(add(openingsPtr, 0x1e0))
            let gate_1_eval := addmod(addmod(w1_0, key_0, p), c, p)
            gate_1_eval := pow7(gate_1_eval, p)
            gate_1_eval := addmod(gate_1_eval, sub(p, w1_1), p)
            gate_1_eval := mulmod(gate_1_eval, q_mimc, p)
            lhs := addmod(lhs, mulmod(rolling_v, gate_1_eval, p), p)

            rolling_v := mulmod(rolling_v, v_challenge, p)
            }

            {
            // Gate 2: q_mimc_opening * ((w2_openings[0] + key_openings[0] + c_opening) ^ 7 - w2_openings[1]) 
            let q_mimc := mload(openingsPtr)
            let c := mload(add(openingsPtr, 0x20))
            let key_0 := mload(add(openingsPtr, 0x1e0))
            let w2_0 := mload(add(openingsPtr, 0x180))
            let w2_1 := mload(add(openingsPtr, 0x1a0))
            let gate_2_eval := addmod(addmod(w2_0, key_0, p), c, p)
            gate_2_eval := pow7(gate_2_eval, p)
            gate_2_eval := addmod(gate_2_eval, sub(p, w2_1), p)
            gate_2_eval := mulmod(gate_2_eval, q_mimc, p)
            lhs := addmod(lhs, mulmod(rolling_v, gate_2_eval, p), p)

            rolling_v := mulmod(rolling_v, v_challenge, p)
            }

            {
            // Gate 3: q_mimc_opening * (key_openings[0] - key_openings[1])
            let q_mimc := mload(openingsPtr)
            let key_0 := mload(add(openingsPtr, 0x1e0))
            let key_1 := mload(add(openingsPtr, 0x200))
            let gate_3_eval := addmod(key_0, sub(p, key_1), p)
            gate_3_eval := mulmod(gate_3_eval, q_mimc, p)
            lhs := addmod(lhs, mulmod(rolling_v, gate_3_eval, p), p)

            rolling_v := mulmod(rolling_v, v_challenge, p)

            // Gate 4: l0 * (key_openings[0] - w0_openings[0] - w0_openings[2])
            let w0_0 := mload(add(openingsPtr, 0xc0))
            let w0_2 := mload(add(openingsPtr, 0x100))
            let l0 := mload(add(verifierTranscript, 0x160))
            let gate_4_eval := addmod(key_0, sub(p, addmod(w0_0, w0_2, p)), p)
            gate_4_eval := mulmod(gate_4_eval, l0, p)
            lhs := addmod(lhs, mulmod(rolling_v, gate_4_eval, p), p)

            rolling_v := mulmod(rolling_v, v_challenge, p)

            // Gate 5: l0 * (nullifierHash - w2_openings[0] - w2_openings[2] - (2 * key_openings[0])) 
            let w2_0 := mload(add(openingsPtr, 0x180))
            let w2_2 := mload(add(openingsPtr, 0x1c0))
            let nullifierHash := mload(add(publicInputs, 0x20))
            let externalNullifier := mload(publicInputs)
            let two_key_0 := addmod(key_0, key_0, p)
            let r := addmod(w2_0, w2_2, p)
            r := addmod(r, two_key_0, p)
            let gate_5_eval := addmod(nullifierHash, sub(p, r), p)
            gate_5_eval := mulmod(gate_5_eval, l0, p)
            lhs := addmod(lhs, mulmod(rolling_v, gate_5_eval, p), p)

            rolling_v := mulmod(rolling_v, v_challenge, p)

            // Gate 6: l0 * (w2_openings[0] - external_nullifier)
            let gate_6_eval := addmod(w2_0, sub(p, externalNullifier), p)
            gate_6_eval := mulmod(gate_6_eval, l0, p)
            lhs := addmod(lhs, mulmod(rolling_v, gate_6_eval, p), p)
            }
        }
        return lhs == rhs;
    }

    function batchInvert(
        uint256[8] memory inputs
    ) internal view returns (uint256[8] memory) {
        uint256[8] memory results;
        uint256 p = Constants.PRIME_R;
        assembly {
            let mPtr := mload(0x40)
            /*
               0x0   b_1 = inputs[1] * inputs[0]
               0x20  b_2 = inputs[2] * b_1
               0x40  b_3 = inputs[3] * b_2
               0x60  b_4 = inputs[4] * b_3
               0x80  b_5 = inputs[5] * b_4
               0xa0  b_6 = inputs[6] * b_5
               0xc0  b_7 = inputs[7] * b_6
               0xe0      = input to modexp precompile
               0x100     = input to modexp precompile
               0x120     = input to modexp precompile
               0x140     = input to modexp precompile
               0x160     = input to modexp precompile
               0x180     = input to modexp precompile
               0x1a0 t_0 = t_1 * inputs[1] (output)
               0x1c0 t_1 = t_2 * inputs[2]
               0x1e0 t_2 = t_3 * inputs[3]
               0x200 t_3 = t_4 * inputs[4]
               0x220 t_4 = t_5 * inputs[5]
               0x240 t_5 = t_6 * inputs[6]
               0x260 t_6 = t_7 * inputs[7]
               0x280 t_7 = inverse(b_7)
               0x2a0 c_1 = t_1 * b_0 (output)
               0x2c0 c_2 = t_2 * b_1 (output)
               0x2e0 c_3 = t_3 * b_2 (output)
               0x300 c_4 = t_4 * b_3 (output)
               0x320 c_5 = t_5 * b_4 (output)
               0x340 c_6 = t_6 * b_5 (output)
               0x360 c_7 = t_7 * b_6 (output)

               Output t_0, c_1, ..., c_7
             */

            // 1. Compute and store b values
            let a_0 := mload(inputs)
            let a_1 := mload(add(inputs, 0x20))
            let b_1 := mulmod(a_0, a_1, p)
            // Store b_1
            mstore(mPtr, b_1)

            for { let i := 1 } lt(i, 8) { i := add(i, 1) } {
                let offset := mul(i, 0x20)
                let a_i := mload(add(inputs, add(offset, 0x20)))
                let b_i_minus_1 := mload(add(mPtr, sub(offset, 0x20)))
                let b_i := mulmod(a_i, b_i_minus_1, p)
                mstore(add(mPtr, offset), b_i)
            }

            // Revert if any of the inputs are 0 (which will cause b_n to be 0)
            switch mload(add(mPtr, 0xc0)) case 0 { revert(0, 0) }


            // 2. Compute and store t_7
            mstore(add(mPtr, 0x0e0), 0x20)
            mstore(add(mPtr, 0x100), 0x20)
            mstore(add(mPtr, 0x120), 0x20)
            mstore(add(mPtr, 0x140), mload(add(mPtr, 0xc0)))
            mstore(add(mPtr, 0x160), sub(p, 2))
            mstore(add(mPtr, 0x180), p)
            let success := staticcall(gas(), 0x05, add(mPtr, 0x0e0), 0xc0, add(mPtr, 0x280), 0x20)
            switch success case 0 { revert(0, 0) }

            // 3. Compute and store t_6, .., t_0
            for { let index := 0 } lt(index, 8) { index := add(index, 1) } {
                let i := sub(7, index)
                let a_i := mload(add(inputs, mul(i, 0x20)))
                let offset := add(0x1a0, mul(i, 0x20))
                let t_i_plus_1 := mload(add(mPtr, offset))
                let t_i := mulmod(a_i, t_i_plus_1, p)
                mstore(add(mPtr, sub(offset, 0x20)), t_i)
            }

            // 6. Compute and store c_1
            let c_1 := mulmod(
                mload(add(mPtr, 0x1c0)),
                mload(inputs),
                p
            )
            mstore(add(mPtr, 0x2a0), c_1)

            // 5. Compute and store c_2, ..., c_7
            for { let i := 2 } lt(i, 8) { i := add(i, 1) } {
                let offst := mul(i, 0x20)
                let t_offst := add(0x1a0, offst)
                let b_offst := mul(sub(i, 2), 0x20)

                let t_i := mload(add(mPtr, t_offst))
                let b_i_minus_1 := mload(add(mPtr, b_offst))

                let c_i := mulmod(t_i, b_i_minus_1, p)

                mstore(add(mPtr, add(offst, 0x280)), c_i)
            }

            mstore(    results,        mload(add(mPtr, 0x01a0))) // t0
            mstore(add(results, 0x20), mload(add(mPtr, 0x02a0))) // c1
            mstore(add(results, 0x40), mload(add(mPtr, 0x02c0))) // c2
            mstore(add(results, 0x60), mload(add(mPtr, 0x02e0))) // c3
            mstore(add(results, 0x80), mload(add(mPtr, 0x0300))) // c4
            mstore(add(results, 0xa0), mload(add(mPtr, 0x0320))) // c5
            mstore(add(results, 0xc0), mload(add(mPtr, 0x0340))) // c6
            mstore(add(results, 0xe0), mload(add(mPtr, 0x0360))) // c7
        }

        return results;
    }
}
