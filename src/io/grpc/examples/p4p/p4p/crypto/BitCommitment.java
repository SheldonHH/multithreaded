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
import java.security.GeneralSecurityException;

import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.StopWatch;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 * This is a bit commitment. It only allows committing to the value of either 0
 * or 1, i.e. a bit. The class also includes a ZKP that proves that the 
 * commmitment contains either 0 or 1.
 *
 * @author ET 08/28/2005
 */

public class BitCommitment extends Commitment implements Serializable{
    private static final long serialVersionUID = 6529685098267757690L;
    public BitCommitment(NativeBigInteger g, NativeBigInteger h) {
        super(g, h);
    }

    /**
     * Commit to a bit
     */
    public BigInteger commit(BigInteger val) {
        if(!val.equals(BigInteger.ZERO) && !val.equals(BigInteger.ONE))
            throw new IllegalArgumentException("BitCommitment.commit can only"
                    + "be invoked with 0 or 1!");
        return super.commit(val);
        // Commitment is smart enough to avoid doing 
        // exponetiation if val is either 0 or 1.
    }


    /**
     * Commit to a bit
     */
    public BigInteger commit(int val) {
        if(val != 0 && val != 1)
            throw new IllegalArgumentException("BitCommitment.commit can only"
                    + "be invoked with 0 or 1!");

        return super.commit(new BigInteger(String.valueOf(val)));
        // Commitment is smart enough to avoid doing exponetiation 
        // if val is either 0 or 1.
    }

    public BigInteger commit(int val, BigInteger r) {
        if(val != 0 && val != 1)
            throw new IllegalArgumentException("BitCommitment.commit can only"
                    + "be invoked with 0 or 1!");

        return super.commit(new BigInteger(String.valueOf(val)), r);
        // Commitment is smart enough to avoid doing exponetiation 
        // if val is either 0 or 1.
    }

    /**
     * Commit to a bit
     */
    public BigInteger commit(boolean val) {
        return commit(val ? 1 : 0);
    }

    /**
     * Commit to a bit
     */
    public BigInteger commit(boolean val, BigInteger r) {
        return commit(val ? 1 : 0, r);
    }

    // The verifier:
    /**
     * Verify if the given bit <code>val</code> is contained in the commitment
     * <code>c</code>. All computations are done using the parameters of this 
     * commitment.
     */
    public boolean verify(BigInteger c, BigInteger val, BigInteger r) {
        if(!val.equals(BigInteger.ZERO) && !val.equals(BigInteger.ONE))
            return false;

        return super.verify(c, val, r);
    }

    public Proof getProof() {
        BitCommitmentProof proof = new BitCommitmentProof();
        proof.construct();
        return proof;
    }

    // f(r) = h^r. The onw way group homomorphism
    public BigInteger f(BigInteger i){
        return h.modPow(i, P4PParameters.p);
    }


    /**
     * A zero-knowledge proof that the commitment contains a bit. The protocol 
     * is based on the f-preimage proof of
     * <p>
     *     <i>Ronald Cramer, Ivan Damg\aard, Zero-Knowledge Proofs for Finite 
     *     Field Arithmetic or: Can Zero-Knowledge Be for Free?, Lecture Notes 
     *     in Computer Science, Volume 1462, Jan 1998, Page 424</i>
     */
    public class BitCommitmentProof extends Proof implements Serializable{
        private static final long serialVersionUID = 6529685098267757690L;
        public BitCommitmentProof() { super(); }

        // Construct the ZKP that the commitment contains a bit
        public void construct() {
            if(val == null)
                throw new RuntimeException("Must commit to a bit first"
                        + "before constructing the proof!");

            commitment = new BigInteger[3];
            commitment[0] = new NativeBigInteger(commit(val, r));
            /**
             * The first element is the commitment itself. Note we must use our 
             * own randomness here since we already committed to a bit. 
             * Otherwise we will get a different commitment and the verifier 
             * may get confused (it depends on the homomorphism).
             */
            challenge = new BigInteger[1];
            response = new BigInteger[4];

            BigInteger v = Util.randomBigInteger(P4PParameters.q);;
            BigInteger e1 = null;
            BigInteger z1 = null;
            BigInteger e0 = null;
            BigInteger z0 = null;
            BigInteger m0 = null;
            BigInteger m1 = null;

            if(val.equals(BigInteger.ZERO)) {
                e1 = Util.randomBigInteger(P4PParameters.q);;
                z1 = Util.randomBigInteger(P4PParameters.q);;
                // calculate m0, m1:
                m0 = f(v);

                /**
                 * Note: NativeBigInteger seems to be unable to handle negative 
                 * exponents properly. We should avoid using 
                 * modPow(e1.negate(), p) before we fix the implementation.
                 */
                BigInteger t = (commitment[0].modInverse(P4PParameters.p)).modPow(e1, P4PParameters.p);
                // c^ -e1 
                t = t.multiply(g.modPow(e1, P4PParameters.p));
                m1 = (t.multiply(f(z1))).mod(P4PParameters.p); // f(z1) * c ^ (-e1) * g ^ e1

                commitment[1] = m0;
                commitment[2] = m1;
                // Get challenge which should be a hash of the commitment:
                BigInteger s = null;
                try {
                    s = Util.secureHash(commitment, P4PParameters.q);
                    challenge[0] = s;
                }
                catch(GeneralSecurityException e) {
                    System.err.println("Can't compute hash!");
                    e.printStackTrace();
                }
                // Compute response:
                e0 = (s.subtract(e1)).mod(P4PParameters.q); //e0 = s - e1;
                z0 = v.add(e0.multiply(r)).mod(P4PParameters.q); // v + e0 * r;
            }
            else if(val.equals(BigInteger.ONE)) {
                e0 = Util.randomBigInteger(P4PParameters.q);;
                z0 = Util.randomBigInteger(P4PParameters.q);;

                // calculate m0, m1:
                m1 = f(v);
                m0 = f(z0).multiply((commitment[0].modInverse(P4PParameters.p)).modPow(e0, P4PParameters.p));
                // f(z0) * c ^ (-e0)

                commitment[1] = m0;
                commitment[2] = m1;
                // Get challenge which should be a hash of the commitment:
                BigInteger s = null;
                try {
                    s = Util.secureHash(commitment, P4PParameters.q);
                    challenge[0] = s;
                }
                catch(GeneralSecurityException e) {
                    System.err.println("Can't compute hash!");
                    e.printStackTrace();
                }
                e1 = s.subtract(e0).mod(P4PParameters.q); //e1 = s - e0;
                z1 = v.add(e1.multiply(r)).mod(P4PParameters.q); // v + e1 * r;
            }
            else
                throw new RuntimeException("Not a bit commitment!");

            response[0] = e0;
            response[1] = e1;
            response[2] = z0;
            response[3] = z1;
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

    public boolean verify(Proof proof) {
        BigInteger[] c = proof.getCommitment();
        BigInteger[] s = proof.getChallenge();
        BigInteger[] r = proof.getResponse();

        if(c.length != 3 || s.length != 1 || r.length != 4)
            return false;

        return verify(c[0], c[1], c[2], s[0], r[0], r[1], r[2], r[3]);
    }


    private boolean verify(BigInteger c, BigInteger m0, BigInteger m1,
                           BigInteger s, BigInteger e0, BigInteger e1,
                           BigInteger z0, BigInteger z1) {

        // Also need to verify the hash
        BigInteger[] msg = new BigInteger[3];
        msg[0] = c;
        msg[1] = m0;
        msg[2] = m1;

        try {
            if(!s.equals(Util.secureHash(msg, P4PParameters.q))) {
                System.out.println("Challenge is not equal to the hash!");
                return false;
            }
        }
        catch(GeneralSecurityException e) {
            System.out.println("GeneralSecurityException!");
            e.printStackTrace();
            return false;
        }

        // Pass 1:
        if(!s.equals((e0.add(e1)).mod(P4PParameters.q))) {
            System.out.println("Verification failed 1");
            return false;
        }

        // Pass 2:
        BigInteger vv = (m0.multiply(c.modPow(e0, P4PParameters.p))).mod(P4PParameters.p);  // m0*c ^ e0
        if(!f(z0).equals(vv)) {
            System.out.println("Verification failed 2");
            return false;
        }

        // Pass 3;
        //NativeBigInteger nvv = new NativeBigInteger(bit_c.multiply(g.modInverse(p)));
        NativeBigInteger nvv =
                new NativeBigInteger(c.multiply(g.modInverse(P4PParameters.p)).mod(P4PParameters.p));
        vv = nvv.modPow(e1, P4PParameters.p); //m1 * (c/y)^e1
        vv = (vv.multiply(m1)).mod(P4PParameters.p);
        if(!f(z1).equals(vv)) {
            System.out.println("Verification failed 3. f(z1) = " + f(z1)
                    + ", vv = " + vv);
            return false;

        }

        return true;
    }


    /**
     * Test the BitCommitment and the ZKP
     */
    public static void main(String[] args) {
        int k = 512;
        int N = 32;
        int nLoops = 100;

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
                else if(arg.equals("-N")) {
                    try {
                        N = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        N = 32;
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
        NativeBigInteger g =  P4PParameters.getGenerator();
        NativeBigInteger h =  P4PParameters.getFreshGenerator();
        // We should use the same generators for both the prover and the verifier.

        BitCommitment bc = new BitCommitment(g, h);

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

        System.out.println("Testing BitCommitment for " + nLoops + " loops .");
        StopWatch proverWatch = new StopWatch();
        StopWatch verifierWatch = new StopWatch();
        long start = System.currentTimeMillis();
        for(int j = 0; j < nLoops; j++) {
            int val = rand.nextBoolean() ? 1 : 0;
            BigInteger c = bc.commit(val);

            System.out.println("Committed to " + val);

            // Verify
            System.out.print("Testing commitment verification ...");
            if(!bc.verify(c, new BigInteger(String.valueOf(val)),
                    bc.getRandomness()))
                System.out.println("Verification failed for test " + j
                        + ". Should have passed.");
            else
                System.out.println(" passed");

            // Wrong randomness. Should fail:
            if(bc.verify(c, new BigInteger(String.valueOf(val)),
                    Util.randomBigInteger(P4PParameters.q)))
                System.out.println("Verification passed for test " + j
                        + ". Should have failed (wrong r).");
            // Wrong value. Should fail:
            if(bc.verify(c, Util.randomBigInteger(P4PParameters.q), bc.getRandomness()))
                System.out.println("Verification passed for test " + j
                        + ". Should have failed (wrong value).");

            // Test the ZKP:
            System.out.print("Testing bit commitment ZKP ...");

            proverWatch.start();
            Proof proof = bc.getProof();
            proverWatch.pause();

            BitCommitment verifier = new BitCommitment(g, h);
            // Construct a new BitCommitment to verify so that the verifier does not
            // have access to the preimage, only the common public parameters.

            verifierWatch.start();
            if(!verifier.verify(proof))
                System.out.println("ZKP failed for test " + j
                        + ". Should have passed.");
            else
                System.out.println(" passed");
            verifierWatch.pause();
        }
        long end = System.currentTimeMillis();
        verifierWatch.stop();
        proverWatch.stop();
        System.out.println("Bit commitment ZKP: " + nLoops
                + " loops. ms per loop:");
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




