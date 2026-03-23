package io.contexa.contexacore.std.security;

public record MemoryReadDecision(
        boolean allowed,
        String decision) {

    public static MemoryReadDecision allow(String decision) {
        return new MemoryReadDecision(true, decision);
    }

    public static MemoryReadDecision deny(String decision) {
        return new MemoryReadDecision(false, decision);
    }
}