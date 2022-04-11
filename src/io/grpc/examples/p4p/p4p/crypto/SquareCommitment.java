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
import java.security.GeneralSecurityException;

import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.StopWatch;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 *
 * Given two numbers, a and b with b = a^2 mod q, produces two commitments s.t.
 * A = C(a), B = C(b) and a ZKP that proves, in zero-knowledge, that the 
 * the number contained in B is the square of the number contained in A.
 * <p>
 * The proof is adapted from
 * <p>
 *   <i>John Canny, Collaborative Filtering with Privacy, IEEE Conf. on 
 *   Security and Privacy, Oakland CA, May 2002.</i>
 * <p>
 * Some changes are made so that we work with commitment rather than ElGamal
 * encryption as in Canny's paper. The new proof works as follows:
 * <p>
 * <ol>
 *  <li>P computes
 *   <ul>  
 *   <li> A = g^a*h^sa mod p, B = g^b*h^sb mod p
 *   <li> x, ra, rb <- rand{0, 1, ... q-1}
 *   <li> Ca = g^x*h^ra, Cb = A^x*h^rb (= g^(a*x)*h^(sa*x+rb))
 *   </ul>
 *  </li>
 * <p>
 *  <li>
 *    P sends to V: A, B, Ca, Cb
 *  </li>
 * <p>
 *  <li>
 *   V sends to P: c <- rand{0, 1, ... q-1}
 *  </li>
 * <p>
 *  <li>
 *   P sends to V: v = c*a + x mod q, za = c*sa + ra mod q, zb = c*(sb - a*sa) + rb
 *  </li>
 * <p>
 *  <li>V checks:
 *    <ul>
 *    <li>g^v*h^za = A^c*Ca mod p?
 *    <li>A^v*h^zb = B^c*Cb mod p?
 *    </ul>
 *  </li>
 *</ol>
 *
 * @author ET 11/10/2005
 */


public class SquareCommitment extends Commitment implements Serializable{
    private static final long serialVersionUID = 6529685098267757690L;
    private BigInteger a = null;
    private BigInteger b = null;
    private NativeBigInteger A = null;
    private NativeBigInteger B = null;
    private BigInteger sa = null;
    private BigInteger sb = null;

    public SquareCommitment(NativeBigInteger g, NativeBigInteger h) {
        super(g, h);
    }

    /**
     * Commits to the number <code>val</code>. The method actually produces two 
     * <code>Commitment</code>s (A and B from the above description). Only A is
     * returned. B could be retrived by getB. 
     * @param  val  the number to commit to
     * @return A
     */
    public BigInteger commit(BigInteger val) {
        a = val;    // Must take mod q
        A = new NativeBigInteger(super.commit(a));
        sa = getRandomness();
        b = a.multiply(a).mod(P4PParameters.q);
        B = new NativeBigInteger(super.commit(b));
        sb = getRandomness();

        return A;
    }

    /**
     * Commits to <code>a</code> using the given randomness. The method actually 
     * produces two <code>Commitment</code>s (A and B). Only A is returned. B 
     * could be retrived by getB. 
     * @param  val  the number to commit to
     * @param  r    the randomness to be used to commit to <code>a</code>
     * @return A
     */
    public BigInteger commit(BigInteger val, BigInteger r) {
        a = val;
        A = new NativeBigInteger(computeCommitment(a, r));
        if(P4PParameters.debug) {
            if(!A.equals(computeCommitment(a.mod(P4PParameters.q), r)))
                throw new RuntimeException("A is not correct!");
        }
        sa = r;
        b = a.multiply(a).mod(P4PParameters.q);
        if(P4PParameters.debug) {
            if(!b.equals(a.mod(P4PParameters.q).multiply(a.mod(P4PParameters.q)).mod(P4PParameters.q)))
                throw new RuntimeException("b (should be a^2) is not correct!");
        }

        sb = Util.randomBigInteger(P4PParameters.q);
        B = new NativeBigInteger(computeCommitment(b, sb));

        return A;
    }

    /**
     * Gets the commitments
     */
    public BigInteger getA() {
        return A;
    }

    public BigInteger getB() {
        return B;
    }

    /**
     * Gets the randomness
     */
    public BigInteger getSa() {
        return sa;
    }

    public BigInteger getSb() {
        return sb;
    }

    /**
     * Constructs the square commitment proof.
     */
    public Proof getProof() {
        SquareCommitmentProof proof = new SquareCommitmentProof();
        proof.construct();
        return proof;
    }


    /**
     * A zero-knowledge proof that two commitments contain a number and its 
     * square. The protocol is based on
     * <p>
     *     <i>John Canny, Collaborative Filtering with Privacy, IEEE Conf. on 
     *     Security and Privacy, Oakland CA, May 2002.</i>
     *
     */
    public class SquareCommitmentProof extends Proof implements Serializable {
        private static final long serialVersionUID = 6529685098267757690L;
        public SquareCommitmentProof() { super(); }

        // Construct the ZKP that the commitment contains a bit
        public void construct() {
            if(A == null || B == null)
                throw new RuntimeException("Must commit to the numbers before"
                        + " constructing the proof!");
            commitment = new BigInteger[4];
            commitment[0] = A;
            commitment[1] = B;
            BigInteger x = Util.randomBigInteger(P4PParameters.q);
            BigInteger ra = Util.randomBigInteger(P4PParameters.q);
            BigInteger rb = Util.randomBigInteger(P4PParameters.q);

            commitment[2] = g.modPow(x, P4PParameters.p).multiply(h.modPow(ra, P4PParameters.p)).mod(P4PParameters.p);  // Ca
            commitment[3] = A.modPow(x, P4PParameters.p).multiply(h.modPow(rb, P4PParameters.p)).mod(P4PParameters.p);  // Cb
            // The first two elements are the commitments to a and b.
            // The next two elements are Ca and Cb

            challenge = new BigInteger[1];

            // Get the challenge which should be a hash of the commitment:
            BigInteger c = null;
            try {
                c = Util.secureHash(commitment, P4PParameters.q);
                challenge[0] = c;
            }
            catch(GeneralSecurityException e) {
                System.err.println("Can't compute hash!");
                e.printStackTrace();
            }

            response = new BigInteger[3];

            // 	    response[0] = a.multiply(c).add(x).mod(q);                             // v
            // 	    response[1] = sa.multiply(c).add(ra).mod(q);                           // za
            // 	    response[2] = sb.subtract(sa.multiply(a)).multiply(c).add(rb).mod(q);  // zb

            BigInteger a1 = a.mod(P4PParameters.q);
            response[0] = a1.multiply(c).add(x).mod(P4PParameters.q);                    // v
            response[1] = sa.multiply(c).add(ra).mod(P4PParameters.q);                   // za
            response[2] = sb.subtract(sa.multiply(a1)).multiply(c).add(rb)
                    .mod(P4PParameters.q);  // zb
        }
    }


    /**
     * Verifies the given proof using our own parameters.
     * <p>
     * The ZKP should be passed to some verifier to verify. The verifier,  
     * who does not have the values, should construct a fresh new commitment
     * and pass the proof to it. The verifier and the prover should use the
     * same parameters (e.g. g and h).
     */
    public boolean verify(Proof proof) {
        BigInteger[] c = proof.getCommitment();
        BigInteger[] s = proof.getChallenge();
        BigInteger[] r = proof.getResponse();

        if(c.length != 4 || s.length != 1 || r.length != 3)
            return false;

        return verify(c[0], c[1], c[2], c[3], s[0], r[0], r[1], r[2]);
    }

    private boolean verify(BigInteger A, BigInteger B, BigInteger Ca,
                           BigInteger Cb, BigInteger c, BigInteger v,
                           BigInteger za, BigInteger zb) {
        // Also need to verify the hash
        BigInteger[] msg = new BigInteger[4];
        msg[0] = A;
        msg[1] = B;
        msg[2] = Ca;
        msg[3] = Cb;

        try {
            if(!c.equals(Util.secureHash(msg, P4PParameters.q))) {
                System.out.println("Challenge is not equal to the hash!");
                return false;
            }
        }
        catch(GeneralSecurityException e) {
            System.out.println("GeneralSecurityException!");
            e.printStackTrace();
            return false;
        }



        // Pass 1: g^v*h^za = A^c*Ca mod p?
        if(!g.modPow(v, P4PParameters.p).multiply(h.modPow(za, P4PParameters.p)).mod(P4PParameters.p)
                .equals(A.modPow(c, P4PParameters.p).multiply(Ca).mod(P4PParameters.p))) {
            System.out.println("Pass 1: g^v*h^za = A^c*Ca mod p failed.");
            return false;
        }

        // Pass 2: A^v*h^zb = B^c*Cb mod p?
        BigInteger vv = Cb.multiply(B.modPow(c, P4PParameters.p)).mod(P4PParameters.p);
        if(!vv.equals(A.modPow(v, P4PParameters.p).multiply(h.modPow(zb, P4PParameters.p)).mod(P4PParameters.p))) {
            System.out.println("Pass 2: A^v*h^zb = B^c*Cb mod p failed.");
            return false;
        }

        return true;
    }


    /**
     * Test the SquareCommitment and the ZKP
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
                else if(arg.equals("-d")) {
                    P4PParameters.debug = true;
                }
            }
        }

        // Setup the parameters:
        P4PParameters.initialize(k, false);
        NativeBigInteger g =  P4PParameters.getGenerator();
        NativeBigInteger h =  P4PParameters.getFreshGenerator();
        // We should use the same generators for both the prover and the verifier.

        SquareCommitment sc = new SquareCommitment(g, h);
        SquareCommitment verifier = new SquareCommitment(g, h);
        // Construct a new SquareCommitment to verify. 

        System.out.println("Testing SquareCommitment for " + nLoops + " loops .");
        StopWatch proverWatch = new StopWatch();
        StopWatch verifierWatch = new StopWatch();
        long start = System.currentTimeMillis();
        for(int j = 0; j < nLoops; j++) {
            BigInteger a = Util.randomBigInteger(P4PParameters.q);
            BigInteger r = Util.randomBigInteger(P4PParameters.q);
            sc.commit(a.negate(), r);
            //sc.commit(a, r);

            // Test the ZKP:
            System.out.print("Testing square commitment ZKP ...");
            proverWatch.start();
            SquareCommitmentProof proof = (SquareCommitmentProof)sc.getProof();
            proverWatch.pause();

            verifierWatch.start();
            if(!sc.verify(proof))
                System.out.println("ZKP failed for test " + j
                        + ". Should have passed.");
                // how do we test failed zkp?
            else
                System.out.println(" passed");
            verifierWatch.pause();
        }
        verifierWatch.stop();
        proverWatch.stop();
        long end = System.currentTimeMillis();
        System.out.println("Square commitment ZKP: " + nLoops
                + " loops. ms per loop:");
        System.out.println("\n  Prover time         Verifier time        Total");
        System.out.println("===================================================");
        System.out.println("    "
                + (double)proverWatch.getElapsedTime()/(double)nLoops
                + "                 "
                + (double)verifierWatch.getElapsedTime()/(double)nLoops
                + "              "
                + (double)(proverWatch.getElapsedTime()+verifierWatch
                .getElapsedTime())/(double)nLoops);



    }
}
