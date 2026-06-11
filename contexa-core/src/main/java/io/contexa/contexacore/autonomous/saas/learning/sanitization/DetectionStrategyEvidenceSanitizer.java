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
 * Generalizes strategy evidence into tenant-safe family facts.
 */
public class DetectionStrategyEvidenceSanitizer extends AbstractLearningEvidenceSanitizer {

    @Override
    protected String generalizeSensitiveFact(String fact) {
        String normalized = fact.toLowerCase(Locale.ROOT);
        if (normalized.contains("path") || normalized.contains("request")) {
            return "Sequence and surface-transition evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("device")) {
            return "Device-context divergence evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("geo")) {
            return "Geographic-context divergence evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("session") || normalized.contains("user") || normalized.contains("tenant")) {
            return "Tenant-private strategy evidence was generalized to a family-level abnormality fact.";
        }
        return "Strategy evidence was generalized to a tenant-safe family-level fact.";
    }

    @Override
    protected String fallbackFact() {
        return "Strategy evidence was generalized to a tenant-safe family-level fact.";
    }
}