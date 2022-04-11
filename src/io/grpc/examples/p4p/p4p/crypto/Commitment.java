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

import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 *
 * This is a commitment scheme based on Pedersen's discrete log-based 
 * commitment scheme:
 * <p>
 *    <i>Torben Pryds Pedersen, Non-interactive and Information-Theoretic Secure 
 *    Verifiable Secret Sharing, CRYPTO 91, Lecture Notes in Computer Science, 
 *    Volume 576, Jan 1992, Page 129.</i>
 * <p>
 * @author ET 08/28/2005
 */

public class Commitment extends P4PParameters implements Serializable {
    private static final long serialVersionUID = 6529685098267757690L;
    protected NativeBigInteger g = null;
    protected NativeBigInteger h = null;

    /**
     * verify that the parameters are correct.
     */

    public void sanityCheck() {
        if(!g.modPow(q, p).equals(BigInteger.ONE))
            throw new IllegalArgumentException("g does not have the correct order!");

        if(!h.modPow(q, p).equals(BigInteger.ONE))
            throw new IllegalArgumentException("h does not have the correct order!");
    }

    // The committer:

    /**
     * The value to be committed to.
     */
    protected BigInteger val = null;

    /**
     * The randomness used in the commitment.
     */
    protected BigInteger r = null;

    /**
     */
    public Commitment(NativeBigInteger g, NativeBigInteger h) {
        this.g = g;
        this.h = h;
        sanityCheck();
    }

    /**
     * Compute the commitment using the given value and randomness.
     * Make this method final to prevent subclass from overiding it.
     */
    protected final BigInteger computeCommitment(BigInteger val,
                                                 BigInteger r) {
        //BigInteger rr = r.mod(q);

        if(val.equals(BigInteger.ONE))
            return g.multiply(h.modPow(r, p)).mod(p);
        else if (val.equals(BigInteger.ZERO))
            return h.modPow(r, p).mod(p);

        /**
         * Note: NativeBigInteger seems to be unable to handle negative 
         * exponents properly. We need to use mod q to make sure the exponents
         * are all non-negative.
         */
        //return g.modPow(val, p).multiply(h.modPow(r, p)).mod(p);
        return g.modPow(val.mod(q), p).multiply(h.modPow(r, p)).mod(p);
    }


    /**
     * Commit to a long
     */

    public BigInteger commit(long val) {
        return commit(new BigInteger(new Long(val).toString()));
    }

    /**
     * Commit to a number in Z_q
     */

    public BigInteger commit(BigInteger val) {
        r = Util.randomBigInteger(q);
        this.val = val;
        return computeCommitment(val, r);
        /**
         * Do not call commit() because it maybe overridden by
         * subclasses.
         */
    }

    /**
     * Commit to a number in Z_q using the given randomness
     */

    public BigInteger commit(BigInteger val, BigInteger r) {
        this.r = r.mod(q);
        this.val = val;

        return computeCommitment(this.val, this.r);
    }


    /**
     * Return the randomness used in this commitment
     */
    public BigInteger getRandomness() {
        return r;
    }

    /**
     * Return the vector contained in this commitment
     */
    public BigInteger getValue() {
        return val;
    }


    // The verifier:
    /**
     * Verify if the given triple consist a valid commitment using the 
     * paramenter of this commitment.
     *
     * @param	c	the possible commitment to test
     * @param	val	the value
     * @param	r   the randomness
     * @return  true if c = commit(val, r)
     */
    public boolean verify(BigInteger c, BigInteger val, BigInteger r) {
        BigInteger cc = computeCommitment(val, r);
        return cc.equals(c);
    }
}




