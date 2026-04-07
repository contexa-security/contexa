package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

import java.util.Map;
import java.util.Optional;

/**
 * Interface for resolving a specific profile type from metadata and canonical context.
 * Each profile type (SessionNarrative, WorkProfile, RoleScope, etc.) has its own resolver.
 *
 * @param <T> the profile type this resolver produces
 */
public interface ProfileResolver<T> {

    /**
     * Resolve a profile from metadata and existing canonical context.
     * Returns empty if the profile has no meaningful data.
     */
    Optional<T> resolve(Map<String, Object> metadata, CanonicalSecurityContext context);

    /**
     * Check if the profile contains meaningful data.
     */
    boolean hasData(T profile);

    /**
     * Build a human-readable summary for the profile.
     */
    String buildSummary(T profile, CanonicalSecurityContext context);

    /**
     * Apply the resolved profile to the canonical context.
     */
    void apply(T profile, CanonicalSecurityContext context);
}
