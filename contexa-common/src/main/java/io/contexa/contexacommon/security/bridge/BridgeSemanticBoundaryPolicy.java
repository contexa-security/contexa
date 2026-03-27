package io.contexa.contexacommon.security.bridge;

import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Bridge-stage calculations must stay on the evidence packaging side.
 * This policy class centralizes labels that distinguish:
 * - explicit customer-provided security facts
 * - structural bridge-discovery heuristics
 * - runtime continuity fallbacks
 * - heuristic hints that must not be promoted to semantic conclusions
 */
public final class BridgeSemanticBoundaryPolicy {

    public static final String EXPLICIT_CUSTOMER_SIGNAL = "EXPLICIT_CUSTOMER_SIGNAL";
    public static final String STRUCTURAL_DISCOVERY_ONLY = "STRUCTURAL_DISCOVERY_ONLY";
    public static final String DERIVED_RUNTIME_FALLBACK = "DERIVED_RUNTIME_FALLBACK";
    public static final String HEURISTIC_HINT_ONLY = "HEURISTIC_HINT_ONLY";
    public static final String BRIDGE_COMPLETENESS_ONLY = "BRIDGE_COMPLETENESS_ONLY";
    public static final String UNAVAILABLE = "UNAVAILABLE";

    private BridgeSemanticBoundaryPolicy() {
    }

    public static String explicitOrUnavailable(@Nullable Object value) {
        return value != null ? EXPLICIT_CUSTOMER_SIGNAL : UNAVAILABLE;
    }

    public static void putStructuralSelectionMetadata(
            Map<String, Object> attributes,
            String selectedAttributeKey,
            String selectedAttributeValue,
            int structuralMatchScore) {
        if (attributes == null) {
            return;
        }
        attributes.put(selectedAttributeKey, selectedAttributeValue);
        attributes.put("bridgeStructuralMatchScore", structuralMatchScore);
        attributes.put("bridgeStructuralMatchPurpose", STRUCTURAL_DISCOVERY_ONLY);
    }

    public static List<String> privilegedAuthoritySignals(Collection<String> authorities) {
        if (authorities == null || authorities.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> signals = new LinkedHashSet<>();
        for (String authority : authorities) {
            if (authority == null || authority.isBlank()) {
                continue;
            }
            String normalized = authority.toUpperCase();
            if (normalized.contains("ADMIN")
                    || normalized.contains("ROOT")
                    || normalized.contains("SUPER")
                    || normalized.contains("PRIVILEGED")) {
                signals.add(authority);
            }
        }
        return List.copyOf(signals);
    }

    public static List<String> immutableDistinct(@Nullable Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return List.copyOf(new LinkedHashSet<>(values));
    }

    public static List<String> nonBlankValues(@Nullable Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> normalized = new ArrayList<>();
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                normalized.add(value);
            }
        }
        return immutableDistinct(normalized);
    }
}
