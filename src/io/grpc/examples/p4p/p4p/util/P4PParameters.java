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

package io.grpc.examples.p4p.p4p.util;

import java.math.BigInteger;
import java.security.SecureRandom;

import io.grpc.examples.p4p.net.i2p.util.NativeBigInteger;

/**
 * P4P's system parameters. All other classes should extend this class 
 * for convenience.
 *
 * @author ET 08/25/2005
 */




public class P4PParameters {

    // Some stock data so we don't have to regenerate each time:
    // They are only for k = 1024
    private static final int STOCK_KEYLENGTH = 1024;
    private static final NativeBigInteger stockGenerator =
            new NativeBigInteger("8945233336956698362120177067658291"
                    + "28255625208609698309729458795223"
                    + "49396662770007144857569313631459"
                    + "20064360628000030948027798897077"
                    + "55461205478680557442064556237153"
                    + "30649683667030965996044852791989"
                    + "41778705800268487243367278278177"
                    + "57680922766893249532793153472346"
                    + "79451792389616055285368469984611"
                    + "514432943342316234");


    private static final BigInteger stockP =
            new BigInteger("14204141203743585258566708349066642260709474"
                    + "89706010686425903591779003193311472507702673"
                    + "03975169399075173941371951568437196865177081"
                    + "24766661530875946683423656535798466913209746"
                    + "91940897642403748131430917204600254122858278"
                    + "97680703356400654227036427049904277395433196"
                    + "219915047607909704021494961357173648661147427");


    private static final BigInteger stockQ =
            new BigInteger("71020706018717926292833541745333211303547374"
                    + "485300534321295179588950159665573625385133"
                    + "651987584699537586970685975784218598432588"
                    + "540623833307654379733417118282678992334566"
                    + "048734597044882120187406571545860230012706"
                    + "142913948840351678200327113518213524952138"
                    + "697716598109957523803954852010747480678586"
                    + "824330573713");

    private static SecureRandom rand = null;

    // Warming up:
    static {
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
        }
        catch(java.security.NoSuchAlgorithmException e) {
            System.err.println("NoSuchAlgorithmException!");
            e.printStackTrace();
            rand = new SecureRandom();
        }

        rand.nextBoolean();
    }

    /**
     * The modulus. Should be at least 1024 bit.
     */
    protected static BigInteger p;

    /**
     * A large prime such that q | p -1. Typically p = 2q + 1
     */
    protected static BigInteger q;

    /**
     * A generator in G_q, the subgroup of order q of Z^*_p.
     * For security reasons we should always work in G_q. This
     * member is private and is used for generating other
     * generators the system may use.
     */
    private static NativeBigInteger generator;
    private static NativeBigInteger[] generators;
    private static int MAX_GENERATORS = 100;

    /**
     * The security parameter. We must guarantee |p| >= k
     */
    protected static int securityParameter;
    private static boolean initialized = false;

    /**
     * Initialize the system parameters with the given security parameter.
     */

    // FIXME: there should also be a method so that the parameters
    // can be read from config file. This way we only distribute the
    // public keys to the users.

    public static void initialize(int k, boolean force) {
        if(initialized && !force) {
            System.out.println("System parameters already initialized.");
            dump();
            return;
        }

        assert(k>0);
        securityParameter = k;

        System.out.println("securityParameter = " + securityParameter);
        System.out.print("Setting up system paramenters. This may take a while,"
                + " depending on the security parameter used ...");

        if(force || k != STOCK_KEYLENGTH) {
            while(true) {
                System.out.print(".");
                q = BigInteger.probablePrime(securityParameter - 1, rand);
                p = (q.add(q)).add(BigInteger.ONE);     // 2*q + 1

                if(p.isProbablePrime(100))
                    break;
            }
        }
        else {
            System.out.println("\nUsing stock p and q.");
            p = stockP;
            q = stockQ;
        }

        //	p = new NativeBigInteger(pp);
        //	q = new NativeBigInteger(qq);

        System.out.println("\np = " + p + "\nq = " + q);

        // Now lets find a generator of G_Q:
        System.out.print("Finding the generator .");
        if(force || k != STOCK_KEYLENGTH) {
            int cnt = 0;
            while(true) {
                cnt++;
                if(cnt%1000 ==0)  System.out.print(".");
                generator = new NativeBigInteger(Util.randomBigInteger(q));
                if(!BigInteger.ONE.equals(generator) &&
                        BigInteger.ONE.equals(generator.modPow(q, p))) {
                    System.out.println("generator = " + generator);
                    break;
                }
            }

            System.out.println("done");
        }
        else {
            System.out.println("\nUsing stock generator.");
            generator = stockGenerator;
        }


        // Generate a lot of generators for use with vector commitment:
        // FIXME: many applications may not need the following.
        generators = new  NativeBigInteger[MAX_GENERATORS];
        for(int i = 0; i < MAX_GENERATORS; i++) {
            BigInteger r = Util.randomBigInteger(q);
            while(r.equals(BigInteger.ZERO))
                r = Util.randomBigInteger(q);
            // r can't be 0

            generators[i] = new NativeBigInteger(generator.modPow(r, p));
        }

        System.out.println("Length of p: " + p.bitLength());
        System.out.println("Length of q: " + q.bitLength());

        if(p.bitLength() < k)
            throw new RuntimeException("p is too small!");

        initialized = true;
    }


    /**
     * Print out the system parameters.
     */
    public static void dump() {
        System.out.println("securityParameter = " + securityParameter);
        System.out.println("\np = " + p + "\nq = " + q);
        System.out.println("generator = " + generator);
        System.out.println("Length of p: " + p.bitLength());
        System.out.println("Length of q: " + q.bitLength());
    }

    /**
     * Note: NativeBigInteger seems to be unable to handle negative 
     * exponents properly. We should avoid using modPow(e1.negate(), p)
     * before we fix the implementation.
     */


    /**
     * Get the first N stock generators in G_q. This maybe useful for vector 
     * commitment.
     */
    public static NativeBigInteger[] getGenerators(int N) {
        if(!initialized)
            throw new RuntimeException("System parameters haven't been "
                    + "setup yet!");
        NativeBigInteger[] v = new  NativeBigInteger[N];

        for(int i = 0; i < N; i++) {
            v[i] = generators[i];
        }
        return v;
    }

    /**
     * Get N fresh generators in G_q. This maybe useful for vector commitment.
     */
    public static NativeBigInteger[] getFreshGenerators(int N) {
        if(!initialized)
            throw new RuntimeException("System parameters haven't been "
                    + "setup yet!");

        NativeBigInteger[] v = new  NativeBigInteger[N];

        for(int i = 0; i < N; i++) {
            BigInteger r = Util.randomBigInteger(q);
            while(r.equals(BigInteger.ZERO))
                r = Util.randomBigInteger(q);
            // r can't be 0

            v[i] = new NativeBigInteger(generator.modPow(r, p));
        }
        return v;
    }

    /**
     * Get the generator in G_q. 
     */
    public static NativeBigInteger getGenerator() {
        if(!initialized)
            throw new RuntimeException("System parameters haven't been "
                    + "setup yet!");
        return generator;
    }

    /**
     * Get a fresh generators in G_q. 
     */
    public static NativeBigInteger getFreshGenerator() {
        if(!initialized)
            throw new RuntimeException("System parameters haven't been "
                    + "setup yet!");

        BigInteger r = Util.randomBigInteger(q);
        while(r.equals(BigInteger.ZERO))
            r = Util.randomBigInteger(q);
        return new NativeBigInteger(generator.modPow(r, p));
    }

    /**
     * Make sure the parameters have the right properties.
     */
    public void sanityCheck() {
        if(!initialized)
            throw new RuntimeException("System parameters haven't been "
                    + "setup yet!");

        if(!p.isProbablePrime(100))
            throw new RuntimeException("p is not prime!");
        if(!q.isProbablePrime(100))
            throw new RuntimeException("q is not prime!");

        if(!generator.modPow(q, p).equals(BigInteger.ONE))
            throw new RuntimeException("generator does not have the "
                    + " correct order!");
    }


    /**
     * Debug helper
     */
    static protected boolean debug = false;
    public static void DEBUG(String msg) {
        if(debug)
            System.out.println(msg);
    }

    public static void DEBUG_(String msg) {
        if(debug)
            System.out.print(msg);
    }
}

