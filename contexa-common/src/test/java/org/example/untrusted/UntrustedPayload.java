package org.example.untrusted;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test fixture outside the Contexa package allowlist. The constructor records every instantiation so
 * tests can prove that deserialization never creates it.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class UntrustedPayload {

    public static final AtomicInteger INSTANTIATIONS = new AtomicInteger();

    private String command;

    public UntrustedPayload() {
        INSTANTIATIONS.incrementAndGet();
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }
}
