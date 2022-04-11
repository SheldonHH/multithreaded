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

import java.util.ArrayList;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileInputStream;

/**
 * A sparse matrix class. It basically stores <row, col, val> touples. By 
 * default the elements are stored in a row major fashion so that it is easy 
 * to be used with current datasets (e.g. EachMovie, TREC).
 *
 * -- Actually the order of entries doesn't matter in matrix-vector 
 * multiplication.
 *
 * @author ET 03/26/2006
 */
public class SparseMatrix { 
    /**
     * MatrixEntry class. Note the row and col start at index 1.
     */
    class MatrixEntry {
        public int row;
        public int col;
        public double val;
        
        public MatrixEntry(int r, int c, double v) {
            row = r;
            col = c;
            val = v;
        }
        
        public String toString() {
            return row + "\t" + col + "\t" + val;
        }
    }
    
    private ArrayList<MatrixEntry> entries = new ArrayList<MatrixEntry>();
    int nRows = 0;
    int nCols = 0;
    boolean transposed = false;
    
    /**
     */
    public int getRows() {
        return nRows;
    }

    /**
     */
    public int getCols() {
        return nCols;
    }
    
    public SparseMatrix() {}
    
    public SparseMatrix(ArrayList<MatrixEntry> entries, int nRows, 
                        int nCols, boolean transposed) {
        this.entries = entries;
        this.nRows = nRows;
        this.nCols = nCols;
        this.transposed = transposed;
    }

    /**
     * Inserts the given entry into the matrix. This method should be called
     * in a row major order.
     */
    public void put(int r, int c, double val) {
        entries.add(new MatrixEntry(r, c, val));
        nRows = r > nRows ? r : nRows;
        nCols = c > nCols ? c : nCols;
        maxAbs = maxAbs < Math.abs(val) ? Math.abs(val) : maxAbs;
    }

    /**
     * Matrix-vector multiplication. Put this matrix times v into w.
     */
    public void multiply(double[] v, int voffset, double[] w, int woffset) {
        for(int i = 0; i < (transposed ? nCols : nRows); i++) {
            w[woffset+i] = 0.;
        }
        
        for(int i = 0; i < entries.size(); i++) {
            MatrixEntry entry = entries.get(i);
            if(transposed)
                w[woffset+entry.col-1] += entry.val*v[voffset+entry.row-1];
            else
                w[woffset+entry.row-1] += entry.val*v[voffset+entry.col-1];
            // Note that in the data, rows and cols start at 1.
        }	
    }
    
    /**
     * Computes A^T*A*v.
     */
    public void ATAv(double[] v, int voffset, double[] w, int woffset) {
        // We first compute Av. Hopefully we have enough memory so we don't 
        // have to implement a sparse vector.
        double[] vv = new double[nRows];
        multiply(v, voffset, vv, 0);
        
        // Then do A^T*vv
        transpose().multiply(vv, 0, w, woffset);
    }

    /**
     * Computes A_i^T*A_i*v.
     * 
     * Note that we asuume that the entries are sorted by their rows,
     * and this method will be called consectively. So we keep a pointer
     * to the current entry, to avoid seeking to that row each time.
     */
    
    int curEntry = 0;
    public void ATAv(int i, double[] v, int voffset, double[] w, int woffset) {
        // Initialize w
      	for(int j = 0; j < nCols; j++) {
            w[woffset+j] = 0.;
        }
        
        // Compute A_i*v, the inner product.
        double s = 0.;	
        MatrixEntry entry = entries.get(curEntry);
        while(entry.row < i) {
            curEntry++;
            curEntry = curEntry%entries.size();
            entry = entries.get(curEntry);
        }
        
        while(entry.row == i) {
            w[woffset+entry.col-1] = entry.val;  // Set the values in w
            
            s += entry.val*v[voffset+entry.col-1];
            curEntry++;
            curEntry = curEntry%entries.size();
            entry = entries.get(curEntry);
        }
        
        // Now scale the vector:
        for(int j = 0; j < nCols; j++) {
            w[woffset+j] = s*w[woffset+j];
        }
    }
    
    private double maxAbs = 0.;   // max |A(i,j)|
    
    public double maxAbs() {
        return maxAbs;
    }
    
    /**
     * Returns density.
     */
    public double getDensity() {
        if(nRows == 0 || nCols == 0) return 0.;
        return (double)entries.size()/(double)(nRows*nCols);
    }
    
    
    /**
     * Dump a few entries.
     */
    public void dump(int n) {
        int len = Math.min(n, entries.size());
        
        for(int i = 0; i < len; i++) {
            System.out.println(entries.get(i));
        }
    }
    
    
    /**
     * Returns the transpose of this matrix. Note that transposed matrix stores
     * data exactly as the original matrix, including the dimensions, i.e. a 
     * n x m matrix A's transpose still has nRows = n and nCols = m. But the 
     * computation  would be different.
     */
    public SparseMatrix transpose() {
        return new SparseMatrix(entries, nRows, nCols, true);	
    }

    /**
     * Load from a file. Shift the values by the given amount. This is 
     * especially for EachMovie dataset because 0 should indicate neutral 
     * vote. maxItems is the max numbers of items to be processed. 
     * maxItems = 0 indicates that all items in the data file should be 
     * processed.
     */
    static public SparseMatrix load(String filename, double shift, 
                                    double threshold, int maxItems) 
        throws IOException { 
        BufferedReader r = 
            new BufferedReader(new InputStreamReader(
                            new FileInputStream(new File(filename))));
        SparseMatrix matrix = new SparseMatrix();        
        
        int cnt = 0;
        int prevRow = -1;
        int prevCol = -1;
        
        String line = r.readLine();
        while (line != null && (maxItems == 0 ? true : cnt < maxItems)) {
            String str[] = line.split("[ \t]");	
            int row = Integer.parseInt(str[0].trim());
            int col = Integer.parseInt(str[1].trim());
            if(prevRow == row && prevCol == col) {
                System.out.println("Warning: repeated entry for row " + row 
                                   + ", col " + col 
                                   + ". Only taking the first and ignoring the rest ...");
                line = r.readLine();
                continue;
            }
            
            double v = Double.parseDouble(str[2].trim()); 
            if(threshold > 0. && v < threshold){
                line = r.readLine();
                continue;
            }
            
            prevRow = row;
            prevCol = col;
            
            matrix.put(row, col, v+shift);
            cnt++;
            line = r.readLine();
        }
        
        r.close();
        
        return matrix;
    }
}
