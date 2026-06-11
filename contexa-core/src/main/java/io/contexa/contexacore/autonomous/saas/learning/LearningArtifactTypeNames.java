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
package io.contexa.contexacore.autonomous.saas.learning;
/**
 * Canonical artifact type names shared across runtime policy, ledger, and runtime suppression.
 */
public final class LearningArtifactTypeNames {
    public static final String DETECTION_STRATEGY = "DETECTION_STRATEGY";
    public static final String DECISION_QUALITY_PROFILE = "DECISION_QUALITY_PROFILE";
    public static final String PROMPT_PRESENTATION = "PROMPT_PRESENTATION";
    public static final String COHORT_SEED = "COHORT_SEED";
    private LearningArtifactTypeNames() {
        throw new IllegalStateException("Utility class");
    }
}
