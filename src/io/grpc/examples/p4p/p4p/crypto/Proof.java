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

import io.grpc.examples.p4p.p4p.util.P4PParameters;

/**
 *
 * This is an abstract 3-round (a.k.a $\Sigma$) proof consisting of 3 rounds:
 * <p>
 *     Prover -> Verifier:  commitment
 *     Verifier -> Prover:  challenge
 *     Prover -> Verifier:  response
 * <p>
 * The proof is made non-interactive by hashing the commitment.
 *
 * @author ET 08/29/2005
 */


public abstract class Proof extends P4PParameters {
    protected BigInteger[] commitment = null;
    /**
     * This is the first message in a 3-round proof. The prover ``commits''
     * to her data using some kind of commitment scheme. This is essentially
     * a sequence of big numbers. Could be computed by one of the 
     * Commitment classes.
     */
    protected BigInteger[] challenge = null;
    /**
     * The second message in the $\Sigma$ proof. Conceptually this is a 
     * random number selected by the verifier. In a non-interactive mode,
     * it is produced by the prover by hashing the commitment.
     */
    protected BigInteger[] response = null;
    /**
     * The third message in the proof.
     */

    public Proof() {}

    public Proof(BigInteger[] commitment, BigInteger[] challenge,
                 BigInteger[] response) {
        this.commitment = commitment;
        this.challenge = challenge;
        this.response = response;
    }

    public BigInteger[] getCommitment() { return commitment; }
    public BigInteger[] getChallenge() { return challenge; }
    public BigInteger[] getResponse() { return response; }

    /**
     * Construct the proof. This should be overriden by subclasses.
     */
    public abstract void construct();

    /**
     * Verify the proof. To be overriden by subclasses.
     */
    //    public abstract boolean verify();

}




