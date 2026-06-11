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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.time.Duration;
import java.util.Map;

/**
 * Abstraction for Zero Trust action storage and retrieval.
 * Implementations: ZeroTrustActionRedisRepository (distributed), InMemoryZeroTrustActionRepository (standalone).
 */
public interface ZeroTrustActionRepository {


    ZeroTrustAction getCurrentAction(String userId);

    ZeroTrustAction getCurrentAction(String userId, String contextBindingHash);

    ZeroTrustAnalysisData getAnalysisData(String userId);

    ZeroTrustAction getActionFromHash(String userId);

    ZeroTrustAction getPreviousActionFromHash(String userId);

    ZeroTrustAction getLastVerifiedAction(String userId);

    long getBlockMfaFailCount(String userId);

    boolean isStale(String userId, long maxAgeMs);


    boolean isBlockMfaPending(String userId);

    void setBlockMfaPending(String userId);

    boolean hasEscalateRetry(String userId);

    void setEscalateRetry(String userId, Duration ttl);


    void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields);

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction);

    void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash);


    void setBlockedFlag(String userId);

    void removeBlockedFlag(String userId);

    void clearBlockMfaPending(String userId);

    long incrementBlockMfaFailCount(String userId);

    void removeAllUserData(String userId);


    void approveOverrideAtomically(String userId, ZeroTrustAction newAction);


    record ZeroTrustAnalysisData(
            String action,
            Double riskScore,
            Double confidence,
            String threatEvidence,
            Integer analysisDepth,
            String updatedAt,
            String reasoning,
            String reasoningSummary,
            String requestId,
            String contextBindingHash,
            String llmProposedAction
    ) {
        public ZeroTrustAnalysisData(
                String action,
                Double riskScore,
                Double confidence,
                String threatEvidence,
                Integer analysisDepth,
                String updatedAt
        ) {
            this(
                    action,
                    riskScore,
                    confidence,
                    threatEvidence,
                    analysisDepth,
                    updatedAt,
                    null,
                    null,
                    null,
                    null,
                    null
            );
        }

        public static ZeroTrustAnalysisData pending() {
            return new ZeroTrustAnalysisData(
                    ZeroTrustAction.PENDING_ANALYSIS.name(),
                    null,  null, null, null, null, null, null, null, null, null
            );
        }
    }
}

