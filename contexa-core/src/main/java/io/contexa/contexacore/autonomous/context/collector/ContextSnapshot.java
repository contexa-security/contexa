package io.contexa.contexacore.autonomous.context.collector;

/**
 * Common interface for all context collector snapshots.
 * Provides a unified contract for accessing snapshot summary.
 */
public interface ContextSnapshot {

    String getSummary();
}
