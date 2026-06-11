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
package io.contexa.contexacore.std.security;

import org.springframework.util.StringUtils;

import java.util.Locale;

public record ContextProvenanceRecord(
        String artifactId,
        String artifactVersion,
        String sourceType,
        String accessScope,
        boolean tenantBound,
        String retrievalPurpose,
        boolean purposeMatch,
        String summary) {

    public ContextProvenanceRecord {
        artifactId = normalize(artifactId);
        artifactVersion = normalize(artifactVersion);
        sourceType = normalize(sourceType);
        accessScope = normalize(accessScope);
        retrievalPurpose = normalize(retrievalPurpose);
        summary = StringUtils.hasText(summary)
                ? summary.trim()
                : String.format(
                        Locale.ROOT,
                        "source=%s,scope=%s,artifact=%s,purpose=%s,match=%s,tenantBound=%s",
                        fallback(sourceType),
                        fallback(accessScope),
                        fallback(artifactId),
                        fallback(retrievalPurpose),
                        purposeMatch,
                        tenantBound);
    }

    private static String fallback(String value) {
        return StringUtils.hasText(value) ? value : "unknown";
    }

    private static String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}