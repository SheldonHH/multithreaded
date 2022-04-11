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

package io.grpc.examples.p4p.p4p.server;

import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Map;

import io.grpc.examples.p4p.p4p.peer.P4PPeer;
import io.grpc.examples.p4p.p4p.user.UserVector2;
import io.grpc.examples.p4p.p4p.util.P4PParameters;
import io.grpc.examples.p4p.p4p.util.Util;
import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 *
 * The P4P server class.
 *
 * @author ET 12/02/2005
 */


/**
 * FIXME:
 *
 * Currently this is just a data structure for holding the server data and
 * methods. The real server should be client-driven and multithreaded. i.e.
 * when there is a client sending data, the server should spawn a thread to
 * handle it. The threat could update the internal state of this class based
 * on actual user data. We are now only using the class in a simulation
 * framework to verify the correctness and the efficiency of the protocols.
 */

public class P4PServer extends P4PParameters {
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
    public int c[][] = null; // The challenge vectors ✈️I.IV send to user
    private long[] s = null;         // The accumulated vector sum
    private long[] peerSum = null;   // The peer's share of the vector sum

    /**
     * A class holding user information, including his data vector (share),
     * its validity ZKP etc.
     */
    public class UserInfo {
        private int ID;
        private long[] v = null;
        private UserVector2.L2NormBoundProof2 proof = null;
        // The L2 norm bound proof. Should be passed to us by the user.
        private BigInteger[] Y = null;
        // The commitments to the peer's share of the checksums.

        public UserInfo(int user, long[] v) {
            ID = user;
            this.v = v;
        }

        /**
         * @return Returns the vector v.
         */
        public long[] getVector() {
            return v;
        }

        /**
         * Update the user vector.
         * @param v The new vector to set.
         */
        public void setVector(long[] v) {
            this.v = v;
        }

        /**
         * @return Returns the user ID.
         */
        public int getID() {
            return ID;
        }

        /**
         * @return Returns the proof.
         */
        public UserVector2.L2NormBoundProof2 getProof() {
            return proof;
        }
        /**
         * Set the l2 norm proof.
         * @param proof The proof to set.
         */
        public void setProof(UserVector2.L2NormBoundProof2 proof) {
            this.proof = proof;
        }

        /**
         */
        public void setY(BigInteger[] Y) {
            this.Y = Y;
        }

        /**
         */
        public BigInteger[] getY() {
            return Y;
        }
    }

    private Hashtable<Integer, UserInfo> usersMap =
            new Hashtable<Integer, UserInfo>();

    /**
     */
    public P4PServer(int m, long F, int l, int N, NativeBigInteger g,
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

        init();
    }

    /**
     */
    public void init() {
        if(s == null)
            s = new long[m];

        for(int i = 0; i < m; i++)
            s[i] = 0;
        usersMap.clear();
    }

    /**
     * Sets a (share of) user vector.
     *
     * @param user   user ID
     * @param v      an m-dimensional vector
     *
     */
    public void setUserVector(int user, long[] v) {
        if(v.length != m)
            throw new IllegalArgumentException("User vector dimension must agree.");

        UserInfo userInfo = usersMap.get(user);
        if(userInfo == null)
            userInfo = new UserInfo(user, v);
        else
            userInfo.setVector(v);

        usersMap.put(user, userInfo);
    }

    /**
     * Disqualify a user and remove his (share of) vector.
     *
     * @param user  user ID
     *
     * @return <code>true</code> if the user is sucessfuly removed.
     *         <code>false</code> if the user is not found in the record.
     */
    public boolean disqualifyUser(int user) {
        return usersMap.remove(user) == null;
    }

    public int getNQulaifiedUsers() {
        return usersMap.size();
    }

    /**
     * Set the l2 norm proof for the given user.
     * @param user The user index.
     * @param proof The proof to set.
     * @return <code>true</code> if the user is sucessfuly updated.
     *         <code>false</code> if the user is not found in the record.
     */
    public boolean setProof(int user, UserVector2.L2NormBoundProof2 proof) {
        UserInfo userInfo = usersMap.get(user);
        if(userInfo == null)
            return false;
        userInfo.setProof(proof);
        return true;
    }

    /**
     * Sets Y for the given user.
     * @param user     The user index.
     * @param Y       The commitments to the peer's share of the checksums
     * @return <code>true</code> if the user is sucessfuly updated.
     *         <code>false</code> if the user is not found in the record.
     */
    public boolean setY(int user, BigInteger[] Y) {
        UserInfo userInfo = usersMap.get(user);
        if(userInfo == null)
            return false;

        userInfo.setY(Y);
        return true;
    }

    /**
     * Generates challenge vectors.
     */
    public void generateChallengeVectors() {
        //  byte[] randBytes = new byte[(int)Math.ceil(2*N*m/8)];
        byte[] randBytes = new byte[2*((int)Math.ceil(N*m/8)+1)];
        // We need twice the random bits in c. We need half of them to flip the 1's
        Util.rand.nextBytes(randBytes);
        int mid = randBytes.length/2;
        c = new int[N][];
        for(int i = 0; i < N; i++) {
            c[i] = new int[m];
            for(int j = 0; j < m; j++) {
                //int byteIndex = (int)2*(i*m + j)/8;
                //int offset = 2*(i*m + j)%8;
                int byteIndex = (i*m + j)>>3;
                int offset = (i*m + j)%8;
                c[i][j] = (randBytes[byteIndex] & (1<<offset)) > 0 ? 1 : 0;
                if(c[i][j] == 1) // flip half of the 1's
                    c[i][j] = (randBytes[mid+byteIndex] & (1<<(offset+1))) > 0 ?
                            1 : -1;
            }
        }
    }

    /**
     */
    public int[][] getChallengeVectors() {
        return c;
    }


    /**
     * The server have received data and their proofs from enough users.
     * This fucntion is then called to compute the sum of the valid vectors.
     */
    public void compute(P4PPeer peer) {
        Object[] users = usersMap.entrySet().toArray();

        UserVector2 uv = new UserVector2(m, F, l, g, h);
        System.out.println("Server:: computing. There are potentially " + usersMap.size()
                + " users.");
        int disqualified = 0;
        for(int i = 0; i < users.length; i++) {
            Map.Entry<Integer, UserInfo> userEntry =
                    (Map.Entry<Integer, UserInfo>)users[i];

            UserInfo user = userEntry.getValue();
            long[] u = user.getVector();

            // Verify its proof:
            uv.setU(u);
            uv.setChecksumCoefficientVectors(c);
            uv.setY(user.getY());
            UserVector2.L2NormBoundProof2 proof = user.getProof();
            if(!uv.verify2(proof)) {
                System.out.println("User " + user.ID
                        + "'s vector failed the verification.");
                disqualifyUser(user.ID);
                // TODO: Must let the peer know about disqualified users so he can computes his share
                // of the sum (the peerSum).
                disqualified++;
                continue;
            }
            Util.vectorAdd(s, u, s, F);
        }
        Util.vectorAdd(s, peer.peerSum, s, F);
        System.out.println("Server:: done computing. " + disqualified + " users disqualified.");
    }

    /**
     */
    public long[] getVectorSum() {
        return s;
    }
}

