package io.grpc.examples.p4p.p4p.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.grpc.examples.p4p.p4p.user.UserVector2;
import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 *
 * A bit vector commitment. It allows the committer to commit to an N-dimensional 
 * vector of bits (0's or 1's). The commitment is a single element in Z_q. It 
 * also includes a ZKP that proves that the commmitment contains a vector of bits 
 * (0's or 1's).
 * <p>
 * NOTE: This class is not used in the new version of the L2-norm ZKP 
 * (implemented in {@link UserVector2}) and is not being maintained.
 *
 *
 * @author ET 08/30/2005
 */

public class BitVectorCommitment extends VectorCommitment {
    // The bit vector
    boolean[] bitVec = null;

    public BitVectorCommitment(NativeBigInteger g[], NativeBigInteger h) {
        super(g, h);
    }

    /**
     * Override this method to prevent users from using a BitVectorCommitment 
     * object to commit to non-bit vectors. Since all commit calls in 
     * VectorCommitment are routed to this method, we should be able to catch 
     * them all here.
     */
    protected BigInteger vectorCommit(BigInteger[] vals, BigInteger r) {
        if(vals.length != N)
            throw new RuntimeException("Incorrect dimension!");

        BigInteger c = h.modPow(r, p);
        for(int i = 0; i < N; i++) {
            if(vals[i].equals(BigInteger.ZERO))
                continue;
            else if(vals[i].equals(BigInteger.ONE))
                c = c.multiply(g[i]).mod(p);
            else
                throw new RuntimeException("Can only commit to bits!");
        }

        return c;
    }

    /**
     * Given a matrix of bits, commit to a column specified by the 
     * 2nd argument. The columns are numbered 0, 1, 2, ..., starting
     * from the LSB. Note that col specifies the position of ``bit'',
     * not ``byte''.
     */

    public BigInteger commit(byte[][] bits, int col) {
        r = Util.randomBigInteger(q);
        return commit(bits, col, r);
    }

    public BigInteger commit(byte[][] bits, int col, BigInteger r) {
        if(bits.length != N)
            throw new RuntimeException("Incorrect dimension!");

        int byteIndex = col/8;   // Which byte this bit belongs to
        int offset = col%8;      // The offset within this byte. Starting from right

        if(col < 0 || byteIndex > bits[0].length) return null;

        bitVec = new boolean[N];   // Number of rows is the size of the bit vector

        BigInteger c = h.modPow(r, p);
        for(int i = 0; i < N; i++) {
            if((bits[i][byteIndex] & (1<<offset)) > 0) {
                bitVec[i] = true;   // This bit is 1
                c = c.multiply(g[i]).mod(p);
            }
            else
                bitVec[i] = false;
            // Nothing to do if the bit is 0
        }

        return c;
    }


    /**
     * Given an array of longs, commit to a bit vector consisting of the 
     * col-th bits of each number. The columns are numbered 0, 1, 2, ..., 
     * starting from the LSB. Note that col specifies the position of 
     * ``bit'', not ``byte''.
     */

    public BigInteger commit(long[] vals, int col) {
        boolean[] bits = new boolean[vals.length];

        for(int i = 0; i < vals.length; i++) {
            String bs = Long.toBinaryString(vals[i]);
            int len = bs.length();
            if(len <= col)
                bits[i] = false;   // It is a 0
            else
                bits[i] = (bs.charAt(len-col-1) == '1');
        }

        return commit(bits);
    }


    /**
     * Commit to a bit vector.
     */

    public BigInteger commit(boolean[] bits) {
        r = Util.randomBigInteger(q);
        return commit(bits, r);
    }

    public BigInteger commit(boolean[] bits, BigInteger r) {
        if(bits.length != N)
            throw new RuntimeException("Incorrect dimension! N = " + N
                    + ", vector size = " + bits.length);
        bitVec = bits;
        BigInteger c = h.modPow(r, p);
        for(int i = 0; i < N; i++) {
            if(bits[i]) {
                c = c.multiply(g[i]).mod(p);
            }
            // Nothing to do if the bit is 0
        }

        return c;
    }

    /**
     * Return the bit vector contained in this commitment
     */
    public boolean[] getBitVector() {
        return bitVec;
    }

    // The verifier:
    /**
     * Verify if the given vector is the one contained in the commitment.
     */
    public boolean verify(BigInteger c, boolean[] vec, BigInteger r) {
        BigInteger cc = commit(vec, r);
        return cc.equals(c);
    }

    /**
     * A zero-knowledge proof that the commitment contains a bit vector. 
     * This proof consists of N parallel bit commitment proofs which
     * are constructed by BitCommitment. We store the bit vector 
     * commitment in the member commitment[0].
     */
    public class BitVectorCommitmentProof extends Proof {
        BitCommitment.BitCommitmentProof[] bitProofs;

        // Construct the ZKP that the commitment contains a bit
        public void construct() {
            commitment = new BigInteger[1];
            commitment[0] = commit(bitVec, r);
            // Store the commitment in commitment[0]

            bitProofs = new BitCommitment.BitCommitmentProof[N];

            BitCommitment bc;
            BigInteger rr = BigInteger.ZERO;

            for(int i = 0; i < N - 1; i++) {
                bc = new BitCommitment(g[i], h);
                BigInteger c = bc.commit(bitVec[i]);
                rr = rr.add(bc.getRandomness()).mod(q);
                bitProofs[i] = (BitCommitment.BitCommitmentProof)bc.getProof();
            }
            // The last one:
            bc = new BitCommitment(g[N-1], h);
            rr = r.subtract(rr).mod(q);
            BigInteger c = bc.commit(bitVec[N-1], rr);
            bitProofs[N-1] = (BitCommitment.BitCommitmentProof)bc.getProof();
        }

        public BitCommitment.BitCommitmentProof[] getBitProofs() {
            return bitProofs;
        }
    }

    public Proof getProof() {
        BitVectorCommitmentProof proof = new BitVectorCommitmentProof();
        proof.construct();
        return proof;
    }


    // The ZKP verify
    public boolean verify(Proof proof) {
        BitVectorCommitmentProof bvProof = (BitVectorCommitmentProof)proof;
        BitCommitment.BitCommitmentProof[] bitProofs = bvProof.getBitProofs();

        BigInteger c = BigInteger.ONE;
        BitCommitment bc;

        for(int i = 0; i < N; i++) {
            bc = new BitCommitment(g[i], h);
            if(!bc.verify(bitProofs[i])) {
                return false;
            }
            c = c.multiply(bitProofs[i].getCommitment()[0]).mod(p);
            // The first element in the proof's commitment is the 
            // bit commitment itself,            
        }

        // Now check the commitment itself:
        if(!c.equals(bvProof.getCommitment()[0])) {
            System.out.println("Homomorphism does not hold. ");
            return false;
        }

        return true;
    }

    /**
     * Test the BitVectorCommitment. One run produced:
     *
     *  ./bin/p4p p4p.BitVectorCommitment -d -k 1024 -l 600
     *
     * Total time: 2046921 ms. Average: 3411.535 ms per loop
     *
     * This is with N = 32.
     *
     * Note that the binding of the commitment is probabilistic and 
     * has failure probability of 1/q. So using small key size may
     * cause some false commitments to pass the verification. This
     * should be OK since any real application should use large q.
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
                else if(arg.equals("-d")) {
                    debug = true;
                }
            }
        }

        System.out.println("k = " + k);
        System.out.println("N = " + N);
        System.out.println("nLoops = " + nLoops);

        // Setup the parameters:
        P4PParameters.initialize(k, false);
        BitVectorCommitment bvc =
                new BitVectorCommitment(getGenerators(N),
                        getGenerator());

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
        // Generate the vector:
        boolean[] vec = new boolean[N];
        boolean[] dummy = new boolean[N];

        System.out.println("Testing BitVectorCommitment for " + nLoops + " loops .");
        long start = System.currentTimeMillis();
        for(int i = 0; i < nLoops; i++) {
            for(int j = 0; j < N; j++) {
                vec[j] = rand.nextBoolean();
                dummy[j] = rand.nextBoolean();
            }

            BigInteger c = bvc.commit(vec);

            // Verify
            System.out.print("Testing commitment verification ...");
            if(!bvc.verify(c, vec, bvc.getRandomness()))
                System.out.println("Verification failed for test "
                        + i + ". Should have passed.");
            else
                System.out.println(" passed");

            // Wrong randomness. Should fail:
            if(bvc.verify(c, vec, Util.randomBigInteger(q)))
                System.out.println("Verification passed for test "
                        + i + ". Should have failed (wrong r submitted).");

            // Wrong value. Should fail:	    
            if(bvc.verify(c, dummy, bvc.getRandomness()))
                System.out.println("Verification passed for test "
                        + i + ". Should have failed (wrong vector submitted).");

            // Test the ZKP:
            System.out.print("Testing bit vector commitment ZKP ...");

            Proof proof = bvc.getProof();
            if(!bvc.verify(proof))
                System.out.println("ZKP failed for test " + i + ". Should have passed.");
            else
                System.out.println(" passed");
        }
        long end = System.currentTimeMillis();
        System.out.println("Total time: " + (end-start) + " ms. Average: "
                + (double)(end-start)/(double)nLoops + " ms per loop");

    }
}




