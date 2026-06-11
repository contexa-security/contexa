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
package io.contexa.contexacore.autonomous.saas.learning.sanitization;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Shared tenant-safe evidence sanitization logic for cross-tenant learning artifacts.
 */
public abstract class AbstractLearningEvidenceSanitizer {

    public List<String> sanitize(List<String> facts) {
        if (facts == null || facts.isEmpty()) {
            return List.of(fallbackFact());
        }
        Set<String> sanitized = new LinkedHashSet<>();
        for (String fact : facts) {
            if (fact == null || fact.isBlank()) {
                continue;
            }
            String normalized = fact.trim();
            sanitized.add(requiresGeneralization(normalized)
                    ? generalizeSensitiveFact(normalized)
                    : normalized);
            if (sanitized.size() >= 6) {
                break;
            }
        }
        if (sanitized.isEmpty()) {
            sanitized.add(fallbackFact());
        }
        return List.copyOf(sanitized);
    }

    protected boolean requiresGeneralization(String fact) {
        String normalized = fact.toLowerCase(Locale.ROOT);
        return normalized.contains("tenant")
                || normalized.contains("user")
                || normalized.contains("session")
                || normalized.contains("correlation")
                || normalized.contains("request")
                || normalized.contains("path")
                || normalized.contains("geo")
                || normalized.contains("deviceid")
                || normalized.contains("userid")
                || normalized.contains("clientip")
                || normalized.contains("artifactid")
                || normalized.contains("/")
                || normalized.contains("=");
    }

    protected abstract String generalizeSensitiveFact(String fact);

    protected abstract String fallbackFact();
}