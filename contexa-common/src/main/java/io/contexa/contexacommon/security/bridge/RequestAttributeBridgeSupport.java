package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

import java.util.*;
import java.util.function.ToIntFunction;

public final class RequestAttributeBridgeSupport {

    private RequestAttributeBridgeSupport() {
    }

    public static Optional<ResolvedRequestAttribute> resolveBest(
            HttpServletRequest request,
            String preferredAttribute,
            List<String> attributeCandidates,
            boolean autoDiscover,
            ToIntFunction<Object> scoreFunction) {
        if (request == null || scoreFunction == null) {
            return Optional.empty();
        }

        if (preferredAttribute != null && !preferredAttribute.trim().isBlank()) {
            Object explicitCandidate = request.getAttribute(preferredAttribute.trim());
            if (explicitCandidate != null) {
                int explicitScore = scoreFunction.applyAsInt(explicitCandidate);
                if (explicitScore > 0) {
                    return Optional.of(new ResolvedRequestAttribute(preferredAttribute.trim(), explicitCandidate, explicitScore));
                }
            }
        }

        ResolvedRequestAttribute bestMatch = null;
        Set<String> visited = new LinkedHashSet<>();
        if (attributeCandidates != null) {
            for (String candidateName : attributeCandidates) {
                if (candidateName == null) {
                    continue;
                }
                String normalized = candidateName.trim();
                if (normalized.isBlank() || !visited.add(normalized)) {
                    continue;
                }
                Object candidate = request.getAttribute(normalized);
                if (candidate == null) {
                    continue;
                }
                int score = scoreFunction.applyAsInt(candidate);
                if (score <= 0) {
                    continue;
                }
                if (bestMatch == null || score > bestMatch.score()) {
                    bestMatch = new ResolvedRequestAttribute(normalized, candidate, score);
                }
            }
        }

        if (!autoDiscover) {
            return Optional.ofNullable(bestMatch);
        }

        Enumeration<String> attributeNames = request.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            String attributeName = attributeNames.nextElement();
            if (!visited.add(attributeName)) {
                continue;
            }
            Object candidate = request.getAttribute(attributeName);
            if (candidate == null) {
                continue;
            }
            int score = scoreFunction.applyAsInt(candidate);
            if (score <= 0) {
                continue;
            }
            if (bestMatch == null || score > bestMatch.score()) {
                bestMatch = new ResolvedRequestAttribute(attributeName, candidate, score);
            }
        }

        return Optional.ofNullable(bestMatch);
    }

    public record ResolvedRequestAttribute(String attributeName, Object attributeValue, int score) {
        public ResolvedRequestAttribute {
            Objects.requireNonNull(attributeName, "attributeName");
            Objects.requireNonNull(attributeValue, "attributeValue");
        }
    }
}
