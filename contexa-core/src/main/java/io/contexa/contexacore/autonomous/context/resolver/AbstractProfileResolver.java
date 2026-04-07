package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.IdentityTokenNormalizer;
import io.contexa.contexacore.autonomous.context.support.MetadataValueResolver;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Abstract base for ProfileResolver implementations.
 * Provides common template method pattern and metadata access utilities.
 * Subclasses implement doResolve(), doHasData(), doBuildSummary(), and doApply().
 */
public abstract class AbstractProfileResolver<T> implements ProfileResolver<T> {

    @Override
    public final Optional<T> resolve(Map<String, Object> metadata, CanonicalSecurityContext context) {
        T profile = doResolve(metadata, context);
        if (profile == null || !doHasData(profile)) {
            return Optional.empty();
        }
        return Optional.of(profile);
    }

    @Override
    public final boolean hasData(T profile) {
        return profile != null && doHasData(profile);
    }

    @Override
    public final String buildSummary(T profile, CanonicalSecurityContext context) {
        if (!hasData(profile)) {
            return null;
        }
        return doBuildSummary(profile, context);
    }

    /**
     * Build the profile from metadata and context. Return null if no data available.
     */
    protected abstract T doResolve(Map<String, Object> metadata, CanonicalSecurityContext context);

    /**
     * Check if the profile has meaningful data.
     */
    protected abstract boolean doHasData(T profile);

    /**
     * Build a human-readable summary for this profile.
     */
    protected abstract String doBuildSummary(T profile, CanonicalSecurityContext context);

    // Common metadata access helpers delegating to MetadataValueResolver

    protected String text(Object... values) {
        return MetadataValueResolver.firstText(values);
    }

    protected Long toLong(Object... values) {
        return MetadataValueResolver.resolveLong(values);
    }

    protected Boolean toBool(Object... values) {
        return MetadataValueResolver.resolveBoolean(values);
    }

    protected Integer toInt(Object... values) {
        return MetadataValueResolver.resolveInteger(values);
    }

    protected Double toDouble(Object... values) {
        return MetadataValueResolver.resolveDouble(values);
    }

    protected List<Integer> toIntList(Object... values) {
        return MetadataValueResolver.resolveIntegerList(values);
    }

    protected List<String> strings(Object... values) {
        return MetadataValueResolver.normalizeStrings(values);
    }

    protected List<String> roles(Object... values) {
        return IdentityTokenNormalizer.normalizeRoleStrings(values);
    }

    protected List<String> authorities(Object... values) {
        return IdentityTokenNormalizer.normalizeAuthorityStrings(values);
    }

    protected List<String> permissions(Object... values) {
        return IdentityTokenNormalizer.normalizePermissionStrings(values);
    }
}
