/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpSession;

import java.util.*;
import java.util.function.ToIntFunction;

public final class SessionBridgeSupport {

    private SessionBridgeSupport() {
    }

    public static Optional<ResolvedSessionAttribute> resolveBest(
            HttpSession session,
            String preferredAttribute,
            List<String> attributeCandidates,
            boolean autoDiscover,
            ToIntFunction<Object> scoreFunction) {
        if (session == null || scoreFunction == null) {
            return Optional.empty();
        }

        if (preferredAttribute != null && !preferredAttribute.trim().isBlank()) {
            Object explicitCandidate = session.getAttribute(preferredAttribute.trim());
            if (explicitCandidate != null) {
                int explicitScore = scoreFunction.applyAsInt(explicitCandidate);
                if (explicitScore > 0) {
                    return Optional.of(new ResolvedSessionAttribute(preferredAttribute.trim(), explicitCandidate, explicitScore));
                }
            }
        }

        ResolvedSessionAttribute bestMatch = null;
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
                Object candidate = session.getAttribute(normalized);
                if (candidate == null) {
                    continue;
                }
                int score = scoreFunction.applyAsInt(candidate);
                if (score <= 0) {
                    continue;
                }
                if (bestMatch == null || score > bestMatch.score()) {
                    bestMatch = new ResolvedSessionAttribute(normalized, candidate, score);
                }
            }
        }

        if (!autoDiscover) {
            return Optional.ofNullable(bestMatch);
        }

        Enumeration<String> attributeNames = session.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            String attributeName = attributeNames.nextElement();
            if (!visited.add(attributeName)) {
                continue;
            }
            Object candidate = session.getAttribute(attributeName);
            if (candidate == null) {
                continue;
            }
            int score = scoreFunction.applyAsInt(candidate);
            if (score <= 0) {
                continue;
            }
            if (bestMatch == null || score > bestMatch.score()) {
                bestMatch = new ResolvedSessionAttribute(attributeName, candidate, score);
            }
        }

        return Optional.ofNullable(bestMatch);
    }

    public record ResolvedSessionAttribute(String attributeName, Object attributeValue, int score) {
        public ResolvedSessionAttribute {
            Objects.requireNonNull(attributeName, "attributeName");
            Objects.requireNonNull(attributeValue, "attributeValue");
        }
    }
}
