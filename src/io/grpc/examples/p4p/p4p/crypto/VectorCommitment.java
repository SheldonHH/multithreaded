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


import java.math.BigInteger;

import io.grpc.examples.p4p.p4p.user.UserVector2;
import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 *
 * Vector commitment. It allows the committer to commit to an N-dimensional 
 * vector. The commitment is a single element in Z_q. The scheme is based on
 * Pedersen's discrete log based commitment scheme:
 * <p>
 *    <i>Torben Pryds Pedersen, Non-interactive and Information-Theoretic Secure 
 *    Verifiable Secret Sharing, CRYPTO 91, Lecture Notes in Computer Science, 
 *    Volume 576, Jan 1992, Page 129</i>
 * <p>
 * NOTE: This class is not used in the new version of the L2-norm ZKP 
 * (implemented in {@link UserVector2}) and is not being maintained.
 *
 * @author ET 08/25/2005
 */

public class VectorCommitment extends P4PParameters {
    protected NativeBigInteger[] g = null;
    protected NativeBigInteger h = null;

    /**
     * The dimension of the vector
     */
    int N = -1;

    /**
     * verify that the parameters are correct.
     */

    public void sanityCheck() {
        super.sanityCheck();

        if(!h.modPow(q, p).equals(BigInteger.ONE))
            throw new IllegalArgumentException("h does not have the correct order!");

        if(N <= 0)
            throw new IllegalArgumentException("Non-positive dimension!");

        for(int i = 0; i < N; i++) {
            if(g[i].equals(BigInteger.ONE))
                throw new IllegalArgumentException("g[" + i + "] is ONE!");
            if(!g[i].modPow(q, p).equals(BigInteger.ONE))
                throw new IllegalArgumentException("g[" + i + "] does not have the correct order!");
        }

    }

    /**
     * This is where all commit calls are routed. Subclass should override this 
     * method if it wants to enforce some restriction (e.g. only allow commiting 
     * to bits). 
     */
    protected BigInteger vectorCommit(BigInteger[] vals, BigInteger r) {
        if(vals.length != N)
            throw new IllegalArgumentException("Incorrect dimension!");

        BigInteger c = h.modPow(r, p);
        for(int i = 0; i < N; i++) {
            if(vals[i].equals(BigInteger.ZERO))
                continue;
            else if(vals[i].equals(BigInteger.ONE))
                c = c.multiply(g[i]).mod(p);
            else
                c = c.multiply(g[i].modPow(vals[i].mod(q), p)).mod(p);
        }

        return c;
    }

    // The committer:
    /**
     * The values to be committed to.
     */
    protected BigInteger[] vals = null;

    /**
     * The randomness used in the commitment.
     */
    protected BigInteger r = null;

    /**
     */
    public VectorCommitment(NativeBigInteger g[], NativeBigInteger h) {
        this.g = g;
        this.h = h;
        N = g.length;
        sanityCheck();
    }

    public int getDemension() { return N; }

    /**
     * Commits to a vector of long integers. (Assume q > Long.MAX_VALUE) 
     */
    public BigInteger commit(long[] vals) {
        this.vals = new BigInteger[vals.length];
        for(int i = 0; i < vals.length; i++)
            this.vals[i] = new BigInteger(String.valueOf(vals[i]));

        return commit(this.vals);
    }


    /**
     * Commits to a vector of long integers using the given randomness
     * (Assume q > Long.MAX_VALUE) 
     */
    public BigInteger commit(long[] vals, BigInteger r) {
        this.vals = new BigInteger[vals.length];
        for(int i = 0; i < vals.length; i++)
            this.vals[i] = new BigInteger(String.valueOf(vals[i]));

        return commit(this.vals, r);
    }


    /**
     * Commits to a vector of integers. (Assume q > Integer.MAX_VALUE) 
     */
    public BigInteger commit(int[] vals) {
        this.vals = new BigInteger[vals.length];
        for(int i = 0; i < vals.length; i++)
            this.vals[i] = new BigInteger(String.valueOf(vals[i]));

        return commit(this.vals);
    }

    /**
     * Commits to a vector of integers using the given randomness. 
     * (Assume q > Integer.MAX_VALUE) 
     */
    public BigInteger commit(int[] vals, BigInteger r) {
        this.vals = new BigInteger[vals.length];
        for(int i = 0; i < vals.length; i++)
            this.vals[i] = new BigInteger(String.valueOf(vals[i]));

        return commit(this.vals, r);
    }

    /**
     * Commits to a vector of BigInteger
     */

    public BigInteger commit(BigInteger[] vals) {
        r = Util.randomBigInteger(q);
        return commit(vals, r);
    }

    /**
     * Commits to a vector of BigInteger using the given randomness
     */

    public BigInteger commit(BigInteger[] vals, BigInteger r) {
        this.r = r;
        this.vals = vals;

        return vectorCommit(vals, r);
    }

    /**
     * Returns the randomness used in this commitment
     */
    public BigInteger getRandomness() {
        return r;
    }

    /**
     * Returns the vector contained in this commitment
     */
    public BigInteger[] getVector() {
        return vals;
    }


    // The verifier:
    /**
     * Verify if the given vector is the one contained in the commitment.
     * All computations are done using the parameters of this commitment.
     */
    public boolean verify(BigInteger c, BigInteger[] vec, BigInteger r) {
        BigInteger cc = vectorCommit(vec, r);
        return cc.equals(c);
    }

    /**
     * Test the VectorCommitment
     */
    public static void main(String[] args) {
        int k = 512;
        int N = 32;
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

        VectorCommitment vc =
                new VectorCommitment(P4PParameters.getGenerators(N),
                        P4PParameters.getGenerator()) ;

        // Generate the vector:
        BigInteger[] vec = new BigInteger[N];
        BigInteger[] sum = new BigInteger[N];

        // dummy
        BigInteger[] dummy = new BigInteger[N];
        for(int i = 0; i < N; i++)
            dummy[i] = Util.randomBigInteger(q);

        System.out.println("Testing VectorCommitment .");
        for(int j = 0; j < nLoops; j++) {
            //System.out.print(".");
            for(int i = 0; i < N; i++) {
                vec[i] = Util.randomBigInteger(q);
                sum[i] = vec[i].add(dummy[i]);
            }

            // Commit
            BigInteger c = vc.commit(vec);
            BigInteger r = vc.getRandomness();

            // Verify
            if(!vc.verify(c, vec, r))
                System.out.println("Verification failed for test "
                        + j + ". Should have passed.");

            // Wrong randomness. Should fail:
            if(vc.verify(c, vec, Util.randomBigInteger(q)))
                System.out.println("Verification passed for test "
                        + j + ". Should have failed (wrong r submitted).");

            // Wrong vector. Should fail:
            if(vc.verify(c, dummy, r))
                System.out.println("Verification passed for test "
                        + j + ". Should have failed (wrong vector submitted).");

            // Now check the homomorphism:
            System.out.print("Verifying homomorphism ....");
            BigInteger dc = vc.commit(dummy);
            BigInteger dr = vc.getRandomness();

            // c*dc = commit(sum, r+dr)
            if(!c.multiply(dc).mod(p).equals(vc.commit(sum, r.add(dr)).mod(p)))
                System.out.println(" failed. Homomorphism doesn't hold.");
            else
                System.out.println(" passed. Homomorphism holds.");
        }
        System.out.println("");
    }
}
