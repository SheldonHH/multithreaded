package io.grpc.examples.p4p.p4p.peer;

import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

public class P4PPeer {
    private NativeBigInteger g = null;
    private NativeBigInteger h = null;

    protected int m = -1;            // The dimension of user vector
    protected long F = -1;
    /**
     * The order of the (small) finite field over which all the computations
     * are carried out. It should be a prime of appropriate bit-length (e.g.
     * 64 bits).
     */

    protected long L = -1;
    protected int l;   // The max number of bits of the 2 norm of user vector
    protected int N = 50;     // The number of chechsums to compute. Default 50
    private int c[][] = null; // The challenge vectors
    public long[] s = null;         // The accumulated vector sum
    public long[] peerSum = null;   // The peer's share of the vector sum


    /**
     * Sets the peer's share of the vector sum
     * @param vv    the sum of the peer's share of the user vector
     */
    public void setPeerSum(long[] vv) {
        peerSum = vv;
    }

    public P4PPeer(int m, long F, int l, int N, NativeBigInteger g,
                     NativeBigInteger h) {
        if(F < 0)
            throw new RuntimeException("Field order must be positive.");

        this.m = m;
        this.F = F;
        this.l = l;
        this.L = ((long)1)<<l - 1;
        this.N = N;
        this.g = g;
        this.h = h;
    }

}
