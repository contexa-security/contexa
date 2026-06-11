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
package io.contexa.contexacommon.enums;

/**
 * Unified risk level model for the Contexa platform.
 *
 * <p>Score boundaries are derived from CVSS v3.0 severity ratings normalized to [0.0, 1.0]:
 * <ul>
 *   <li>LOW [0.0, 0.3): Minimal operational risk, auto-approval eligible</li>
 *   <li>MEDIUM [0.3, 0.6): Moderate risk, single approval typically required</li>
 *   <li>HIGH [0.6, 0.8): Significant risk, may require multi-approval</li>
 *   <li>CRITICAL [0.8, 1.0]: Severe risk, multi-approval mandatory</li>
 * </ul>
 *
 * <p>Note: riskScore is audit/logging metadata in the ZT pipeline.
 * The AI-driven ZeroTrustAction (ALLOW/BLOCK/CHALLENGE/ESCALATE) is the sole decision driver.
 */
public enum RiskLevel {

    LOW(0.0, 0.3),
    MEDIUM(0.3, 0.6),
    HIGH(0.6, 0.8),
    CRITICAL(0.8, 1.0);

    private final double minScore;
    private final double maxScore;

    RiskLevel(double minScore, double maxScore) {
        this.minScore = minScore;
        this.maxScore = maxScore;
    }

    public double getMinScore() {
        return minScore;
    }

    public double getMaxScore() {
        return maxScore;
    }

    /**
     * Maps a numeric risk score [0.0, 1.0] to the corresponding RiskLevel.
     * Boundary values are inclusive on the lower end, exclusive on the upper end,
     * except CRITICAL which includes 1.0.
     */
    public static RiskLevel fromScore(double score) {
        if (score < 0.0) return LOW;
        for (RiskLevel level : values()) {
            if (score >= level.minScore && score < level.maxScore) {
                return level;
            }
        }
        return CRITICAL;
    }
}
