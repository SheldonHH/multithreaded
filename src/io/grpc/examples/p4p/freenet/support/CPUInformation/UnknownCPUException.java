/*
 * Created on Jul 16, 2004
 */
package io.grpc.examples.p4p.freenet.support.CPUInformation;

/**
 * @author Iakin
 *
 */
public class UnknownCPUException extends RuntimeException {
    public UnknownCPUException() {
        super();
    }

    public UnknownCPUException(String message) {
        super(message);
    }
}
