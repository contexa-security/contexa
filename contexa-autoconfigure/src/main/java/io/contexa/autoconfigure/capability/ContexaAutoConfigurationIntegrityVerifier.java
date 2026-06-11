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
package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityCheckResult;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityMode;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class ContexaAutoConfigurationIntegrityVerifier implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(ContexaAutoConfigurationIntegrityVerifier.class);

    private final ContexaCapabilityRegistry registry;
    private final CapabilityRequirementResolver requirementResolver;

    public ContexaAutoConfigurationIntegrityVerifier(
            ContexaCapabilityRegistry registry,
            CapabilityRequirementResolver requirementResolver) {
        this.registry = registry;
        this.requirementResolver = requirementResolver;
    }

    @Override
    public void afterSingletonsInstantiated() {
        CapabilityMode mode = requirementResolver.effectiveMode();
        if (mode == CapabilityMode.OFF) {
            return;
        }

        List<CapabilityCheckResult> results = registry.evaluate();
        List<CapabilityCheckResult> abnormalResults = results.stream()
                .filter(result -> result.status() == CapabilityStatus.DEGRADED
                        || result.status() == CapabilityStatus.INACTIVE_UNEXPECTED
                        || result.status() == CapabilityStatus.FAILED)
                .map(requirementResolver::visibleIssueForCurrentApplication)
                .flatMap(Optional::stream)
                .filter(result -> result.required() || mode == CapabilityMode.STRICT)
                .toList();

        for (CapabilityCheckResult result : abnormalResults) {
            String diagnostic = diagnosticMessage(result);
            if (result.shouldFail(mode)) {
                log.error(diagnostic);
            } else {
                log.warn(diagnostic);
            }
        }

        List<CapabilityCheckResult> failures = results.stream()
                .map(requirementResolver::visibleIssueForCurrentApplication)
                .flatMap(Optional::stream)
                .filter(result -> result.shouldFail(mode))
                .toList();
        if (!failures.isEmpty()) {
            throw new IllegalStateException("Contexa required capability check failed.\n"
                    + failures.stream()
                    .map(this::failureBlock)
                    .collect(Collectors.joining("\n")));
        }
    }

    private String diagnosticMessage(CapabilityCheckResult result) {
        return "[ContexaCapability] " + result.capability().propertyKey()
                + " status=" + result.status()
                + " required=" + result.required()
                + "\n  Reason: " + safe(result.reason())
                + "\n  Missing beans: " + formatBeans(result.missingBeans())
                + "\n  Recommended actions:\n" + formatRecommendations(result.recommendations());
    }

    private String failureBlock(CapabilityCheckResult result) {
        return "- capability: " + result.capability().propertyKey()
                + "\n  reason: " + safe(result.reason())
                + "\n  missing beans: " + formatBeans(result.missingBeans())
                + "\n  recommended actions:\n" + formatRecommendations(result.recommendations());
    }

    private String formatBeans(List<String> beans) {
        if (beans == null || beans.isEmpty()) {
            return "[]";
        }
        return beans.stream().collect(Collectors.joining(", ", "[", "]"));
    }

    private String formatRecommendations(List<String> recommendations) {
        if (recommendations == null || recommendations.isEmpty()) {
            return "    - Inspect the auto-configuration conditions for the missing bean chain.";
        }
        return recommendations.stream()
                .map(recommendation -> "    - " + recommendation)
                .collect(Collectors.joining("\n"));
    }

    private String safe(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }
}
