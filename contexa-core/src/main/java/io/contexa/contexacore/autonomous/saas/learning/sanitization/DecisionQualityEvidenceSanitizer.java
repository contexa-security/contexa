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

import java.util.Locale;

/**
 * Generalizes decision-quality evidence into tenant-safe scenario facts.
 */
public class DecisionQualityEvidenceSanitizer extends AbstractLearningEvidenceSanitizer {

    @Override
    protected String generalizeSensitiveFact(String fact) {
        String normalized = fact.toLowerCase(Locale.ROOT);
        if (normalized.contains("false-positive") || normalized.contains("false negative") || normalized.contains("false_negative")) {
            return "Reviewed outcome bias evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("path") || normalized.contains("request") || normalized.contains("session")) {
            return "Scenario-context evidence was generalized to a tenant-safe decision-quality fact.";
        }
        if (normalized.contains("tenant") || normalized.contains("user") || normalized.contains("geo")) {
            return "Tenant-private decision-quality evidence was generalized to a scenario-level fact.";
        }
        return "Decision-quality evidence was generalized to a tenant-safe scenario fact.";
    }

    @Override
    protected String fallbackFact() {
        return "Decision-quality evidence was generalized to a tenant-safe scenario fact.";
    }
}