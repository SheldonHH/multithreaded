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
import io.grpc.examples.p4p.p4p.util.P4PParameters;

/**
 * 
 * Benchmarks some basic P4P operations such as exponentiation.
 *
 * @author ET 02/20/2006
 */

public class P4PBench extends P4PParameters {
    static private NativeBigInteger g = null;

    public static void main(String[] args) {
	//throws IOException {
	int k = 512;
	int m = 10;
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
		    debug = true;
		}
	    }
	}
	
	System.out.println("k = " + k);
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
	g = P4PParameters.getGenerator();
	
	long expTime = 0;
	long addTime = 0;
	long multTime = 0;
	long innerProductTime = 0;
	
        BigInteger exponent = Util.randomBigInteger(q);
        long start = System.currentTimeMillis();
        for(int i = 0; i < nLoops; i++) {
            g.modPow(exponent, p);
        }
        long end = System.currentTimeMillis();

        System.out.println("expTest: " + nLoops + " loops take " + (end-start) + " ms. Average = " 
                           + (double)(end-start)/(double)nLoops + " ms.");


	// Now do addition:
	NativeBigInteger a = new NativeBigInteger(Util.randomBigInteger(p));
	NativeBigInteger b = new NativeBigInteger(Util.randomBigInteger(p));
	BigInteger c = null;

        start = System.currentTimeMillis();
        for(int i = 0; i < nLoops; i++) {
            a = new NativeBigInteger(a.add(b).mod(p));
        }
        end = System.currentTimeMillis();
	addTime = end - start;
        System.out.println("Addition time: " + nLoops + " loops take " +  addTime + " ms. Average = " 
                           + (double)(addTime)/(double)nLoops + " ms.");

	// Multiply:
        start = System.currentTimeMillis();
        for(int i = 0; i < nLoops; i++) {
            a = new NativeBigInteger(a.multiply(b).mod(p));
        }
        end = System.currentTimeMillis();
	multTime = end - start;
        System.out.println("Multiply time: " + nLoops + " loops take " + (multTime) + " ms. Average = " 
                           + (double)multTime/(double)nLoops + " ms.");
	System.out.println("Multiply time/addition time = " + (double)multTime/(double)addTime);

    }
}

