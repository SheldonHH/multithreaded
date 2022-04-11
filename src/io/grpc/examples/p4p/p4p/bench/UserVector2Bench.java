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

package io.grpc.examples.p4p.p4p.bench;

import java.math.BigInteger;
import java.security.SecureRandom;


import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.p4p.util.StopWatch;
import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.crypto.SquareCommitment;
import io.grpc.examples.p4p.p4p.crypto.Proof;
import io.grpc.examples.p4p.p4p.crypto.BitCommitment;
import io.grpc.examples.p4p.p4p.crypto.Commitment;

import io.grpc.examples.p4p.p4p.user.UserVector;

/**
 * Changes:
 *
 *   12/08/2005: Moved to bench package.
 */


/**
 *
 * This is essentailly the same class as user.UserVector2 as of reversion r15 (until 12/08/2005).
 * As an initial implementation, it only implemented the basic crypographic tools, no real
 * computation. It is good as a benchmarking tool since it contains all the expensive crypto
 * steps. It is moved to this package to preserve the banchmarking capability. Real development
 * will go on in the user package.
 *
 * And this class should be removed once we have port everything to user/ and sim/
 *
 * @author ET 12/08/2005
 */

public class UserVector2Bench extends UserVector {
    private NativeBigInteger g = null;
    private NativeBigInteger h = null;
    private SquareCommitment sc = null;

    /**
     * Constructs a (share of) user vector.
     *
     * @param data  the user vector
     * @param F     the size of the field where all user computations are performed
     * @param l     the max allowed number of bits of the L2 norm of user vector
     * @param g     the first generator used in commitment
     * @param h     the sceond generator used in commitment
     *
     */

    public UserVector2Bench(long[] data, long F, int l, NativeBigInteger g, NativeBigInteger h) {
        super(data, F, l);
        this. g = g;
        this.h = h;
        sc = new SquareCommitment(g, h);
    }


    /**
     * A zero-knowledge proof that the vector L2 norm is bounded by L.
     * <p>
     * This proof uses another method. Namely instead of checking each checksum individually
     * it checks the sum of their squares. This still gives the bound but uses fewer bit
     * commitment proofs. Note that the challenge vectors are chosen from {-1, 0, 1}.
     */
    public class L2NormBoundProof2 extends Proof {
        private long[] checksums = null;
        // Assume there is no overflow

        private SquareCommitment.SquareCommitmentProof[] scProofs = null;   // The square proofs
        private BitCommitment.BitCommitmentProof[] bcProofs = null;             // The bit proof for the sum of the squares

        // Construct the ZKP that the commitment contains a bit
        public void construct() {
            if(c == null)
                throw new RuntimeException("Checksum vector not set yet.");

            checksums = new long[c.length];
            scProofs = new SquareCommitment.SquareCommitmentProof[c.length];
            SquareCommitment sc = new SquareCommitment(g, h);

            // Compute the checksums:
            BigInteger squareSum = BigInteger.ZERO;            // Sum of the squares
            BigInteger squareSumCommitment = BigInteger.ONE;   // Commitment to the sum of the squares
            BigInteger sRandomness = BigInteger.ZERO;

            for(int i = 0; i < c.length; i++) {
// 		checksums[i] = 0;
// 		for(int j = 0; j < m; j++) {
// 		    //s += c[i][j]*data[j];
// 		    if(c[i][j] == 1)
// 		        checksums[i] += data[j];
// 		    else if(c[i][j] == -1)
// 			checksums[i] -= data[j];
//	    }
                checksums[i] = Math.abs(Util.innerProduct(c[i], data));
                /**
                 * Note that although all the normal compuations are done in
                 * a small finite field, we don't restrict the size of the
                 * checksum here (i.e. no mod operation). We allow s to grow
                 * to check the L2 norm of the user vector.
                 */

                BigInteger cs = new BigInteger(new Long(checksums[i]).toString());
                //cs = cs.mod(q);

                //System.out.println("cs = " + cs);

                sc.commit(cs);
                scProofs[i] = (SquareCommitment.SquareCommitmentProof)sc.getProof();

                if(debug) {
                    // lets check here:
                    if(!sc.verify(scProofs[i])) {
                        throw new RuntimeException("Square commitment proof or verification is not working properly. i = " + 1);
                    }
                }

                squareSum = squareSum.add(cs.multiply(cs).mod(q)).mod(q);
                squareSumCommitment = squareSumCommitment.multiply(sc.getB()).mod(p);
                // Now get the randomness used to commit to the square:
                sRandomness = sRandomness.add(sc.getSb()).mod(q);
            }

            if(debug) {
                // Lets verify if we compute the commitment to the sum of squares correcly:
                System.out.print("Checking commitment to sum of squares ...");
                Commitment cm = new Commitment(g, h);
                BigInteger ssc = cm.commit(squareSum, sRandomness);
                if(!ssc.equals(squareSumCommitment)) {
                    throw new RuntimeException("Commitment to sum of squares wasn't computed correctly!");
                }
                System.out.println(" done.");
            }

            // Now we should provide a proof that squareSum contains a number x such
            // that x < 1/2*N*L^2 <=> 2x < N*L^2. L is l bits. N*L^2 will be logN+2l bits
            // This bound will not be tight.

            squareSum = squareSum.add(squareSum).mod(q);   // 2x
            sRandomness = sRandomness.add(sRandomness).mod(q);
            squareSumCommitment = squareSumCommitment.multiply(squareSumCommitment).mod(p);   // 2x

            // Lets check if the commitment was computed correctly:
            if(debug) {
                System.out.print("Checking commitment to 2*(sum of squares) ...");
                Commitment cm = new Commitment(g, h);
                if(!cm.verify(squareSumCommitment, squareSum, sRandomness))
                    throw new RuntimeException("Commitment to 2*(sum of squares) wasn't computed correctly!");
                System.out.println(" done.");
            }

            // Save it in the commitment field
            commitment = new BigInteger[1];
            commitment[0] = squareSumCommitment;

            // 🌟 crux of the test 🌟 //
            int numBits = Math.max(squareSum.bitLength(), Integer.toBinaryString(c.length).length()+2*l);
            // Even for small squares we must do all the commitments otherwise leak info.
            DEBUG("squareSum has " + numBits + " bits");

            bcProofs = new BitCommitment.BitCommitmentProof[numBits];
            BitCommitment bc = new BitCommitment(g, h);
            for(int i = 0; i < numBits - 1; i++) {
                BigInteger cc = bc.commit(squareSum.testBit(i));
                bcProofs[i] = (BitCommitment.BitCommitmentProof)bc.getProof();

                if(debug) {
                    if(!cc.equals(bcProofs[i].getCommitment()[0]))
                        throw new RuntimeException("Bit commitment wasn't computed correctly!");
                }

                BigInteger r = bc.getRandomness();
                BigInteger e = BigInteger.ZERO.setBit(i);    // 2^i
                // Note that we can't use ((long)1)<<i because long doesn't have enough bits!
                sRandomness = sRandomness.subtract(r.multiply(e)).mod(q);
                // -= r[i]*2^i
            }

            // Now the last bit:
            // First need to compute the randomness correctly:
            // BigInteger e = new BigInteger(new Long(((long)1)<<(numBits-1)).toString());   // 2^l
            BigInteger e = BigInteger.ZERO.setBit(numBits-1);    // 2^l
            e = e.modInverse(q);
            sRandomness = sRandomness.multiply(e).mod(q);         // divide by 2^l

            bc.commit(squareSum.testBit(numBits-1), sRandomness);
            bcProofs[numBits-1] = (BitCommitment.BitCommitmentProof)bc.getProof();


            // Lets check it here:
            if(debug) {
                System.out.print("Checking homomorphism ...");
                BigInteger ZZ = BigInteger.ONE;
                BigInteger z = BigInteger.ZERO;

                for(int i = 0; i < numBits; i++) {
                    //BigInteger e = new BigInteger(new Long(((long)1)<<i).toString());  // 2^i
                    e = BigInteger.ZERO.setBit(i);
                    // Note that we can't use ((long)1)<<i because long doesn't have enough bits!

                    if(squareSum.testBit(i))
                        z = z.add(e);

                    NativeBigInteger Z = (NativeBigInteger)bcProofs[i].getCommitment()[0];

                    ZZ = ZZ.multiply(Z.modPow(e, p)).mod(p);
                }

                if(!z.equals(squareSum)) {
                    System.out.println("z = " + z);
                    System.out.println("squareSum = " + squareSum);
                    throw new RuntimeException("2*(sum of squares) wasn't computed correctly!");
                }
                if(!ZZ.equals(squareSumCommitment))
                    throw new RuntimeException("Homomorphism doesn't hold!");

                System.out.println("done");
            }
        }

        public SquareCommitment.SquareCommitmentProof[] getSquareCommitmentProofs() {
            return scProofs;
        }

        public BitCommitment.BitCommitmentProof[] getBitCommitmentProofs() {
            return bcProofs;
        }

        // Pretend we can see the user vector and the checksum. In a real deployment,
        // this function won't exist
        public long[] getChecksums() {
            return checksums;
        }
    }


    public Proof getL2NormBoundProof2() {
        L2NormBoundProof2 proof = new L2NormBoundProof2();
        proof.construct();
        return proof;
    }


    // The verifier:

    // The ZKP verify
    public boolean verify2(Proof proof) {
        L2NormBoundProof2 l2Proof = (L2NormBoundProof2)proof;
        BitCommitment.BitCommitmentProof[] bcProofs = l2Proof.getBitCommitmentProofs();
        SquareCommitment.SquareCommitmentProof[] scProofs = l2Proof.getSquareCommitmentProofs();
        long[] s = l2Proof.getChecksums();


        // Pretend we can see the user vector and the checksum. In a real deployment, they
        // will only be half of them
        for(int i = 0; i < s.length; i++) {
            // First make sure the checksums are computed correctly:
            if(s[i] != Math.abs(Util.innerProduct(c[i], data))) {
                System.out.println("Checksum " + i + " not computed correctly!");
                return false;
            }
        }

        // Next check that the sum of squares does not have excessive bits:
        if(bcProofs.length > Integer.toBinaryString(c.length).length()+2*l) {
            System.out.println("Sum of squares has too many bits: " + bcProofs.length
                    + ", the limit is " + (Integer.toBinaryString(c.length).length()+2*l));
            return false;
        }

        // We actually need to verify that the A in scProofs is commitment to s.
        // This should be done individually by the server and the privacy peer.

        // Check the square proofs:
        SquareCommitment sc = new SquareCommitment(g, h);
        for(int i = 0; i < scProofs.length; i++) {
            if(!sc.verify(scProofs[i])) {
                System.out.println("Square verification " + i + " failed.");
                return false;
            }
        }

        // Now the bit commitment for the sum. First check if the commitment is
        // computed correctly:
        BigInteger z = BigInteger.ONE;
        for(int i = 0; i < scProofs.length; i++) {
            z = z.multiply(scProofs[i].getCommitment()[1]).mod(p);   // *= B
        }
        z = z.multiply(z).mod(p);    // commitment[0] actually stores 2X

        if(!l2Proof.getCommitment()[0].equals(z)) {
            System.out.println("Commitment to square sum wasn't computed correctly.");
            return false;
        }

        // Then check each bits
        BitCommitment bc = new BitCommitment(g, h);
        BigInteger zz = BigInteger.ONE;

        DEBUG("Checking  " + bcProofs.length + " bit commitments");

        BigInteger ZZ = BigInteger.ONE;
        for(int i = 0; i < bcProofs.length; i++) {
            if(!bc.verify(bcProofs[i])) {
                System.out.println("Bit commitment verification " + i + " failed.");
                return false;
            }

            //BigInteger e = new BigInteger(new Long(((long)1)<<i).toString());  // 2^i
            BigInteger e = BigInteger.ZERO.setBit(i);
            // Note that we can't use ((long)1)<<i because long doesn't have enough bits!

            NativeBigInteger Z = (NativeBigInteger)bcProofs[i].getCommitment()[0];
            ZZ = ZZ.multiply(Z.modPow(e, p)).mod(p);
        }

        if(!ZZ.equals(z)) {
            System.out.println("Homomorphism does not hold.");
            return false;
        }

        return true;
    }


    /**
     * Test the UserVector L2 norm bound ZKP.
     *
     * Note that the zkp is probabilistic and its sucess probability is
     * only accurate when m is large, So with small m it may not pass
     * some of the tests.
     *
     */
    public static void main(String[] args) {
        //throws IOException {
        int k = 512;
        int m = 10;
        int nLoops = 10;
        // Now generate some data to be used:
        int l = 40;    // We restrict L to be 32 bits
        boolean doBench = false;
        boolean worstcase = false;
        // test the worst case cost. i.e. every vector should pass. this is when the verifier spends longest time.

        // Definie the number of iterations that the bound ZKP must have:
        int zkpIterations = 50;

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
                else if(arg.equals("-m")) {
                    try {
                        m = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        m = 10;
                    }
                }
                else if(arg.equals("-N")) {
                    try {
                        zkpIterations = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        zkpIterations = 50;
                    }
                }

                else if(arg.equals("-o")) {
                    try {
                        nLoops = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        nLoops = 10;
                    }
                }

                else if(arg.equals("-l")) {
                    try {
                        l = Integer.parseInt(args[i++]);
                    }
                    catch (NumberFormatException e) {
                        l = 40;
                    }
                }

                else if(arg.equals("-d")) {
                    debug = true;
                }
                else if(arg.equals("-w")) {
                    worstcase = true;  // test the worst case cost. i.e. every vector should pass. this is when the verifier spends longest time.
                }
                else if(arg.equals("-bench")) {
                    doBench = true;
                }
            }
        }

        System.out.println("k = " + k);
        System.out.println("m = " + m);
        System.out.println("nLoops = " + nLoops);

        // Setup the parameters:
        P4PParameters.initialize(k, false);
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

        // Lets make l = log_2 (m)
        //int l = Math.max(10, (int)Math.ceil(Math.log(m)/Math.log(2.)));    // We restrict L to be 32 bits
        long L = ((long)2)<<l - 1;
        long F = BigInteger.probablePrime(l+10, rand).longValue();
        // Make the field size to be 10 bits larger than l

        System.out.println("l = " + l + ", L = " + L);
        System.out.println("F = " + F);
        System.out.println("zkpIterations = " + zkpIterations);

        // Generate the data and the checksum coefficient vector:
        long[] data = new long[m];
        int[][] c = new int[zkpIterations][];
        NativeBigInteger[] bi = P4PParameters.getGenerators(2);

        for(int j = 0; j < zkpIterations; j++)
            c[j] = new int[m];

        int nfails = 0;

        if(doBench) {
            System.out.println("Benchmarking UserVector L2 bound ZKP for " + nLoops + " loops .");
            StopWatch proverWatch = new StopWatch();
            StopWatch verifierWatch = new StopWatch();

            //	    long mean = (long)((double)L/Math.sqrt(m));
            long mean = (long)((double)L/Math.sqrt(m));
            System.out.println("mean = " + mean);

            long start = System.currentTimeMillis();
            long innerProductTime = 0;
            long randChallengeTime = 0;
            for(int i = 0; i < nLoops; i++) {
                boolean shouldPass;   // We should create a vector that passes the zkp
                if(worstcase)
                    shouldPass = true;     // Test the worst case
                else {
                    if(i < nLoops/2)
                        shouldPass = true;
                    else
                        shouldPass = false;
                }
                //shouldPass = rand.nextBoolean();
                double l2 = 0.;

                for(int j = 0; j < m; j++) {
                    if(shouldPass) {
                        if(mean > 10)
                            data[j] = Math.abs(rand.nextLong()) % mean;
                        else {
                            if(l2 < L/2)
                                data[j] = 1;
                            else
                                data[j] = 0;
                        }
                        l2 += data[j]*data[j];
                    }

                    else
                        data[j] = Math.abs(rand.nextLong()) % mean * (1+Math.abs(rand.nextInt()%4));
                    //data[j] = (long)Math.abs(rand.nextInt());  // Make it small deliberately
                    //DEBUG("d["+j+"] = " + data[j]);
                }

                byte[] randBytes = new byte[(int)Math.ceil(2*zkpIterations*m/8)];
                long t0 = System.currentTimeMillis();
                rand.nextBytes(randBytes);
                for(int j = 0; j < zkpIterations; j++) {
                    for(int kk = 0; kk < m; kk++) {
// 		        c[j][kk] = rand.nextBoolean() ? 1 : 0;
// 			if(c[j][kk] == 1) // flip half of the 1's
// 			    c[j][kk] = rand.nextBoolean() ? 1 : -1;
                        int byteIndex = (int)2*(j*m + kk)/8;
                        int offset = 2*(j*m + kk)%8;

                        c[j][kk] = (randBytes[byteIndex] & (1<<offset)) > 0 ? 1 : 0;

                        if(c[j][kk] == 1) // flip half of the 1's
                            c[j][kk] = (randBytes[byteIndex] & (1<<(offset+1))) > 0 ? 1 : -1;
                    }
                }

                randChallengeTime += (System.currentTimeMillis() - t0);

                UserVector2Bench uv = new UserVector2Bench(data, F, l, bi[0], bi[1]);
                data = uv.getUserData();

                l2 = 0.;
                for(int j = 0; j < m; j++) {
                    //DEBUG("d["+j+"] = " + data[j]);
                    l2 += (double)data[j]*data[j];
                }

                l2 = Math.sqrt(l2);
                System.out.println("L2 norm of user data = " + l2);

                // Lets test how much time an inner product takes

                t0 = System.currentTimeMillis();
                Util.innerProduct(c[0], data);
                innerProductTime += (System.currentTimeMillis()-t0);

                uv.setChecksumCoefficientVectors(c);
                proverWatch.start();
                L2NormBoundProof2 proof = (L2NormBoundProof2)uv.getL2NormBoundProof2();
                proverWatch.pause();

                shouldPass = l2 < L;     // Correct shouldPass using actual data.
                verifierWatch.start();
                boolean didPass = uv.verify2(proof);
                verifierWatch.pause();

                if(shouldPass != didPass) {
                    nfails++;
                    System.out.println("Test No. " + i + " failed. shouldPass = " + shouldPass + ", result = " + didPass);
                }
                else
                    System.out.println("Test No. " + i + " passed. shouldPass = didPass = " + shouldPass);
            }

            verifierWatch.stop();
            proverWatch.stop();
            long end = System.currentTimeMillis();

            System.out.println("UserVector L2 norm ZKP: " + nLoops + " loops. Failed " + nfails + " times. ms per loop:");
            System.out.println("\n  Prover time         Verifier time        Total");
            System.out.println("===================================================");
            System.out.println("    " + (double)proverWatch.getElapsedTime()/(double)nLoops + "                 "
                    + (double)verifierWatch.getElapsedTime()/(double)nLoops + "              "
                    + (double)(proverWatch.getElapsedTime()+verifierWatch.getElapsedTime())/(double)nLoops);
            System.out.println("Time for doing 1 experiement: " + (double)(end-start)/(double)nLoops);
            System.out.println("Time for doing 1 inner product: " + (double)innerProductTime/(double)nLoops);
            System.out.println("Time for generating N challenge vectors: " + (double)randChallengeTime/(double)nLoops);
        }
        else {
            System.out.println("Testing UserVector L2 bound ZKP for " + nLoops + " loops .");
            long start = System.currentTimeMillis();
            for(int i = 0; i < nLoops; i++) {
                for(int j = 0; j < m; j++) {
                    data[j] = (long)Math.abs(rand.nextInt());  // Make it small deliberately
                    //DEBUG("d["+j+"] = " + data[j]);
                }

                for(int j = 0; j < zkpIterations; j++) {
                    c[j] = new int[m];

                    for(int kk = 0; kk < m; kk++) {
                        c[j][kk] = rand.nextBoolean() ? 1 : 0;
                        if(c[j][kk] == 1) // flip half of the 1's
                            c[j][kk] = rand.nextBoolean() ? 1 : -1;
                    }
                }

                UserVector2Bench uv = new UserVector2Bench(data, F, l, bi[0], bi[1]);
                data = uv.getUserData();

                double l2 = 0.;
                for(int j = 0; j < m; j++) {
                    //DEBUG("d["+j+"] = " + data[j]);
                    l2 += (double)data[j]*data[j];
                }

                l2 = Math.sqrt(l2);
                System.out.println("L2 norm of user data = " + l2);

                uv.setChecksumCoefficientVectors(c);
                L2NormBoundProof2 proof = (L2NormBoundProof2)uv.getL2NormBoundProof2();

                boolean shouldPass = l2 < L;
                boolean didPass = uv.verify2(proof);

                System.out.println("shouldPass = " + shouldPass + ", result = " + didPass);

            }

            long end = System.currentTimeMillis();
            System.out.println("Total time: " + (end-start) + " ms. Average: "
                    + (double)(end-start)/(double)nLoops + " ms per loop");
        }
    }
}

