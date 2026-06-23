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
package io.contexa.contexacore.hcad.semantic;

public enum HcadSemanticEvidenceType {

    USER_NORMAL_BASELINE(
            "user-normal-baseline",
            "user-behavior-baseline-store",
            "user baseline rebuild, embedding model change, or dimension change"),
    SESSION_RECENT_FLOW(
            "session-recent-flow",
            "hcad-observation-window-store",
            "session flow expiry or context binding change"),
    RESOURCE_LLM_DECISION_SUMMARY(
            "resource-llm-decision-summary",
            "ai-security-decision-observation-store",
            "resource, policy, prompt template, embedding model, or dimension change"),
    POLICY_PROMPT_VERSION_SNAPSHOT(
            "policy-prompt-version-snapshot",
            "policy-and-prompt-metadata-store",
            "policy, authorization metadata, or prompt template version change"),
    NORMAL_REQUEST_SIMILARITY(
            "normal-request-similarity",
            "materialized-normal-request-evidence-store",
            "baseline, embedding model, or dimension change"),
    RISK_REQUEST_SIMILARITY(
            "risk-request-similarity",
            "materialized-risk-request-evidence-store",
            "resource, policy, prompt template, embedding model, or dimension change");

    private final String cacheSegment;
    private final String authoritativeSource;
    private final String invalidationScope;

    HcadSemanticEvidenceType(
            String cacheSegment,
            String authoritativeSource,
            String invalidationScope) {
        this.cacheSegment = cacheSegment;
        this.authoritativeSource = authoritativeSource;
        this.invalidationScope = invalidationScope;
    }

    public String cacheSegment() {
        return cacheSegment;
    }

    public String authoritativeSource() {
        return authoritativeSource;
    }

    public String invalidationScope() {
        return invalidationScope;
    }
}
