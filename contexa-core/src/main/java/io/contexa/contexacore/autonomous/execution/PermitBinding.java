package io.contexa.contexacore.autonomous.execution;

public record PermitBinding(
        String permitId,
        String continuityFingerprint) {

    public boolean permitBound() {
        return permitId != null && !permitId.isBlank();
    }
}