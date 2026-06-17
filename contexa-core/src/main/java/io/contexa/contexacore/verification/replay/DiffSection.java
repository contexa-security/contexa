package io.contexa.contexacore.verification.replay;

/**
 * Represents a single difference between two prompt texts.
 * Used for byte-level diff comparison in Deterministic Replay.
 */
public record DiffSection(
        int lineNumber,
        String type,
        String originalLine,
        String reconstructedLine
) {

    public static final String ADDED = "ADDED";
    public static final String REMOVED = "REMOVED";
    public static final String CHANGED = "CHANGED";
}
