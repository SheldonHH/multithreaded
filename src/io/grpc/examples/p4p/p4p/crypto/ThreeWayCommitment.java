/**
 * Copyright (c) 2007 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the University may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package io.grpc.examples.p4p.p4p.crypto;


import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.StopWatch;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 * A 3-Way commitment is a commitment that contains one of three values 
 * {0, -c, c}. A ThreeWayCommitment class only allows committing to one of 
 * these values. The class also includes a ZKP that proves the commmitment
 * contains either 0 or +/- c. The commitment and proof are from
 * <p>
 *   <ul>
 *    <i>Yitao Duan and John Canny. Zero-knowledge Test of Vector 
 *    Equivalence and Granulation of User Data with Privacy. In 2006
 *    IEEE International Conference on Granular Computing (GrC 2006), 
 *    May 10 - 12, Atlanta, USA.</i> 
 *   </ul>
 * <p>
 * The papper is available
 *    <a href="http://www.cs.berkeley.edu/~duan/research/papers/grc06.pdf">here</a>
 *
 * @author ET 10/20/2007
 */

public class ThreeWayCommitment extends Commitment implements Serializable{
    private static final long serialVersionUID = 6529685098267757690L;
    public final NativeBigInteger CONST;    // The public constant

    public ThreeWayCommitment(NativeBigInteger g, NativeBigInteger h,
                              BigInteger c) {
        super(g, h);
        this.CONST = new NativeBigInteger(c.abs());
    }

    public ThreeWayCommitment(NativeBigInteger g, NativeBigInteger h,
                              long c) {
        super(g, h);
        this.CONST = new NativeBigInteger(new BigInteger(String.valueOf(c)).abs());
    }

    /**
     */
    public BigInteger commit(BigInteger val) {
        if(!val.equals(BigInteger.ZERO) && !val.equals(CONST)
                && !val.equals(CONST.negate()))
            throw new RuntimeException("ThreeWayCommitment.commit can only"
                    + "be invoked with 0 or +/-" + CONST);
        return super.commit(val);
        // Commitment is smart enough to avoid doing 
        // exponetiation if val is either 0 or 1.
    }

    /**
     */
    public BigInteger commit(long val) {
        long c = CONST.longValue();
        if(val != 0 && val != c && val != -c)
            throw new RuntimeException("ThreeWayCommitment.commit can only"
                    + "be invoked with 0 or +/-" + c);

        return super.commit(new BigInteger(String.valueOf(val)));
        // Commitment is smart enough to avoid doing exponetiation 
        // if val is either 0 or 1.
    }

    public BigInteger commit(long val, BigInteger r) {
        long c = CONST.longValue();
        if(val != 0 && val != c && val != -c)
            throw new RuntimeException("ThreeWayCommitment.commit can only"
                    + "be invoked with 0 or +/-" + c);

        return super.commit(new BigInteger(String.valueOf(val)), r);
        // Commitment is smart enough to avoid doing exponetiation 
        // if val is either 0 or 1.
    }


    // The verifier:
    /**
     * Verify if the given bit <code>val</code> is contained in the commitment
     * <code>c</code>. All computations are done using the parameters of this 
     * commitment.
     */
    public boolean verify(BigInteger c, BigInteger val, BigInteger r) {
        if(!val.equals(BigInteger.ZERO) && !val.equals(CONST)
                && !val.equals(CONST.negate()))
            return false;

        return super.verify(c, val, r);
    }

    public Proof getProof() {
        ThreeWayCommitmentProof proof = new ThreeWayCommitmentProof();
        proof.construct();
        return proof;
    }

    /**
     * A zero-knowledge proof that the commitment contains 0,or +/-c. The protocol 
     * is based on
     * <p>
     *    <i>Yitao Duan and John Canny. Zero-knowledge Test of Vector 
     *    Equivalence and Granulation of User Data with Privacy. In 2006
     *    IEEE International Conference on Granular Computing (GrC 2006), 
     *    May 10 - 12, Atlanta, USA.</i>
     * <p>
     * The proof essentially consists of two bit commitments <code>C1</code> and 
     * <code>C2</code> (and their proofs (<code>bc1</code> and <code>bc2</code>).
     * The 3-way commitment is just C1^{c}C2^{-c} mod p.
     */
    public class ThreeWayCommitmentProof extends Proof implements Serializable {
        private static final long serialVersionUID = 6529685098267757690L;
        //BigInteger C1 = null;
        //BigInteger C2 = null;
        /**
         * The first element in the BitCommitmentProof is the commitment 
         * itself so we don't need to store the bit commitments.
         */
        private BitCommitment.BitCommitmentProof bcp1 = null;
        private BitCommitment.BitCommitmentProof bcp2 = null;

        public ThreeWayCommitmentProof() { super(); }

        // Construct the ZKP that the commitment contains 0,or +/-c
        public void construct() {
            if(val == null)
                throw new RuntimeException("Must commit to a value first"
                        + "before constructing the proof!");

            // We do need to store this commitment:
            commitment = new BigInteger[1];

            if(val != null)
                commitment[0] = commit(val, r);
            else
                commitment[0] = commit(val);
            // Note: If this ThreeWayCommitment has been used to commit to a 
            // value (indicated by val != null), we should use the same 
            // randomness so that the proof contains the same commitment.

            BitCommitment bc1 = new BitCommitment(g, h);
            BitCommitment bc2 = new BitCommitment(g, h);
            /**
             * We need to make sure that the random numbers in bc1 and bc2 sum 
             * to the random number used in this commitment. So we generate 
             * only 1 random number. Note that since the commitment should be
             * C1^{c}/C2^c no matter what val is, the random numbers associated 
             * with C1, C2, and this commitment should satisfy 
             *
             *    r = (r1 - r2)*c
             *
             */
            BigInteger rc = r.multiply(CONST.modInverse(q)).mod(q);
            // r/c
            if(val.equals(BigInteger.ZERO)) {
                bc2.commit(0);
                bc1.commit(0, rc.add(bc2.getRandomness()).mod(q));
            }
            else if(val.equals(CONST)) {
                bc2.commit(0);
                bc1.commit(1, rc.add(bc2.getRandomness()).mod(q));
            }
            else if(val.equals(CONST.negate())) {
                bc2.commit(1);
                bc1.commit(0, rc.add(bc2.getRandomness()).mod(q));
            }

            /**
             * The first element in the BitCommitmentProof is the commitment 
             * itself so we don't need to store the bit commitment.
             */
            bcp1 = (BitCommitment.BitCommitmentProof)bc1.getProof();
            bcp2 = (BitCommitment.BitCommitmentProof)bc2.getProof();

            BigInteger C1 = bcp1.getCommitment()[0];
            BigInteger C2 = bcp2.getCommitment()[0];
        }

        /**
         * Returns the BitCommitmentProof for C1.
         */
        public BitCommitment.BitCommitmentProof getNumeratorProof() {
            return bcp1;
        }

        /**
         * Returns the BitCommitmentProof for C2.
         */
        public BitCommitment.BitCommitmentProof getDenominatorProof() {
            return bcp2;
        }
    }

    /**
     * Verifies the given proof using our own parameters.
     *
     * The ZKP should be passed to some verifier to verify. The verifier,  
     * who does not have the values, should construct a fresh new commitment
     * and pass the proof to it. The verifier and the prover should use the
     * same parameters (e.g. g and h).
     */

    public boolean verify(ThreeWayCommitmentProof proof) {
        BitCommitment.BitCommitmentProof bcp1 = proof.getNumeratorProof();
        BitCommitment.BitCommitmentProof bcp2 = proof.getDenominatorProof();

        // Check the bit commitments
        BitCommitment bc = new BitCommitment(g, h);
        if(!bc.verify(bcp1) || !bc.verify(bcp2)) {
            System.out.println("BitCommitment verification failed!");
            return false;
        }

        // This commitment
        BigInteger C = proof.getCommitment()[0];
        BigInteger C1 = bcp1.getCommitment()[0];
        BigInteger C2 = bcp2.getCommitment()[0];
        if(!C1.multiply(C2.modInverse(p)).mod(p).modPow(CONST, p).equals(C)) {
            System.out.println("Commitment was not computed correctly.");
            System.out.println("C1: " + C1 + ", C2: " + C2);
            return false;
        }

        return true;
    }


    /**
     * Test the ThreeCommitment and the ZKP
     */
    public static void main(String[] args) {
        int k = 512;
        int nLoops = 10;

        for (int i = 0; i < args.length; ) {
            String arg = args[i++];
            if(arg.length() > 0 && arg.charAt(0) == '-') {
                if (arg.equals("-k")) {
                    try {
                        k = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        k = 512;
                    }
                }
                else if(arg.equals("-l")) {
                    try {
                        nLoops = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        nLoops = 10;
                    }
                }

            }
        }

        // Setup the parameters:
        P4PParameters.initialize(k, false);
        NativeBigInteger g =  getGenerator();
        NativeBigInteger h =  getFreshGenerator();
        // We should use the same generators for both the prover and the verifier.

        SecureRandom rand = null;
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
        }
        catch(java.security.NoSuchAlgorithmException e) {
            System.err.println("NoSuchAlgorithmException!");
            e.printStackTrace();
            rand = new SecureRandom();
        }

        rand.nextBoolean();

        System.out.println("Testing ThreeWayCommitment for " + nLoops + " loops .");
        StopWatch proverWatch = new StopWatch();
        StopWatch verifierWatch = new StopWatch();
        long start = System.currentTimeMillis();
        int nfails = 0;
        for(int j = 0; j < nLoops; j++) {
            long c = rand.nextLong();
            if(k < 66) c = (long)rand.nextInt()%(1<<(k-2));

            if(c < 0) c = -c;
            long val = rand.nextLong();
            if(val%3 == 0)      val = 0;
            else if(val%3 == 1) val = c;
            else                val = -c;

            ThreeWayCommitment tc = new ThreeWayCommitment(g, h, c);
            BigInteger C = tc.commit(val);

            // Verify
            System.out.print("Testing commitment verification No. " + j + "....");
            System.out.println(" Committed to " + val);
            if(!tc.verify(C, new BigInteger(String.valueOf(val)),
                    tc.getRandomness())) {
                System.out.println("Verification failed for test " + j
                        + ". Should have passed.");
                nfails++;
            }

            // Wrong randomness. Should fail:
            if(tc.verify(C, new BigInteger(String.valueOf(val)),
                    Util.randomBigInteger(q))) {
                System.out.println("Verification passed for test " + j
                        + ". Should have failed (wrong r).");
                nfails++;
            }
            // Wrong value. Should fail:
            if(tc.verify(C, Util.randomBigInteger(q), tc.getRandomness())) {
                System.out.println("Verification passed for test " + j
                        + ". Should have failed (wrong value).");
                nfails++;
            }

            // Test the ZKP:
            proverWatch.start();
            Proof proof = tc.getProof();
            proverWatch.pause();

            ThreeWayCommitment verifier = new ThreeWayCommitment(g, h, c);
            // Construct a new BitCommitment to verify so that the verifier does not
            // have access to the preimage, only the common public parameters.

            verifierWatch.start();
            if(!verifier.verify((ThreeWayCommitmentProof)proof)) {
                System.out.println("ZKP failed for test " + j);
                nfails++;
            }
            else
                System.out.println("ZKP passed for test " + j);
            verifierWatch.pause();
        }
        long end = System.currentTimeMillis();
        verifierWatch.stop();
        proverWatch.stop();
        System.out.println("3-Way commitment ZKP: " + nLoops
                + " loops. Total failed tests: " + nfails + ". ms per loop:");
        System.out.println("\n  Prover time         Verifier time        Total");
        System.out.println("===================================================");
        System.out.println("    "
                + (double)proverWatch.getElapsedTime()/(double)nLoops
                + "                 "
                + (double)verifierWatch.getElapsedTime()/(double)nLoops
                + "              "
                + (double)(proverWatch.getElapsedTime()
                +verifierWatch.getElapsedTime())
                /(double)nLoops);
        System.out.println("Total testing time: " + (end-start) + " ms.");
    }
}




