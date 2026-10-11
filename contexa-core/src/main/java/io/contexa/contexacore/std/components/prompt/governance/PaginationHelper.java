package io.contexa.contexacore.std.components.prompt.governance;

/**
 * Common pagination limit validation used across 39+ operation services.
 * Extracted to eliminate duplicate limit normalization code.
 */
public final class PaginationHelper {

    private PaginationHelper() {
    }

    /**
     * Normalize a nullable limit value to a safe bounded integer.
     *
     * @param limit        user-provided limit (may be null or negative)
     * @param defaultLimit fallback when limit is null or non-positive
     * @param maxLimit     upper bound to prevent excessive queries
     * @return normalized limit value within [1, maxLimit]
     */
    public static int safeLimit(Integer limit, int defaultLimit, int maxLimit) {
        return (limit != null && limit > 0) ? Math.min(limit, maxLimit) : defaultLimit;
    }
}
