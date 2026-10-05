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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.std.rag.service.VectorStoreFilterValues;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Removes the engine state of a user whose account is deleted. The engine keys its state by user name, so without
 * this purge a later account with the same name would inherit a permanent BLOCK, the personal baseline, the decision
 * history used as RAG evidence and the open sessions of the deleted account.
 * <p>
 * Every step runs even when an earlier one fails; failures are reported in the result and logged. Audit records,
 * decision observations and sealed evidence are kept: they are retained by their own retention policies.
 * Host applications that delete users outside Contexa call {@link #purge(String)} themselves.
 */
@Slf4j
public class UserEngineStatePurger {

    private static final String RAG_USER_METADATA_KEY = "userId";

    private final ZeroTrustActionRepository actionRepository;
    private final BlockingSignalBroadcaster blockingSignalBroadcaster;
    private final BlockMfaStateStore blockMfaStateStore;
    private final BaselineDataStore baselineDataStore;
    private final SecurityContextDataStore securityContextDataStore;
    private final ColdPathEventProcessor coldPathEventProcessor;
    private final VectorStore vectorStore;
    private final IForceLogoutService forceLogoutService;
    private final List<UserStatePurgeContributor> contributors;

    public UserEngineStatePurger(
            ZeroTrustActionRepository actionRepository,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            BlockMfaStateStore blockMfaStateStore,
            BaselineDataStore baselineDataStore,
            SecurityContextDataStore securityContextDataStore,
            ColdPathEventProcessor coldPathEventProcessor,
            VectorStore vectorStore,
            IForceLogoutService forceLogoutService,
            List<UserStatePurgeContributor> contributors) {
        this.actionRepository = actionRepository;
        this.blockingSignalBroadcaster = blockingSignalBroadcaster;
        this.blockMfaStateStore = blockMfaStateStore;
        this.baselineDataStore = baselineDataStore;
        this.securityContextDataStore = securityContextDataStore;
        this.coldPathEventProcessor = coldPathEventProcessor;
        this.vectorStore = vectorStore;
        this.forceLogoutService = forceLogoutService;
        this.contributors = contributors == null ? List.of() : List.copyOf(contributors);
    }

    public UserEngineStatePurgeResult purge(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId is required");
        }
        List<String> purged = new ArrayList<>();
        Map<String, String> failed = new LinkedHashMap<>();

        step("sessions", forceLogoutService != null,
                () -> forceLogoutService.forceLogoutByUserId(userId, "ACCOUNT_DELETED"), purged, failed);
        step("decision-state", actionRepository != null,
                () -> actionRepository.removeAllUserData(userId), purged, failed);
        step("blocking-signal", blockingSignalBroadcaster != null,
                () -> blockingSignalBroadcaster.registerUnblock(userId), purged, failed);
        step("block-mfa-state", blockMfaStateStore != null,
                () -> blockMfaStateStore.clearUser(userId), purged, failed);
        step("baseline", baselineDataStore != null,
                () -> baselineDataStore.deleteUserBaseline(userId), purged, failed);
        step("security-context", securityContextDataStore != null,
                () -> securityContextDataStore.deleteUserData(userId), purged, failed);
        step("escalation-protection", coldPathEventProcessor != null,
                () -> coldPathEventProcessor.clearUserEscalationProtection(userId), purged, failed);
        step("decision-history", vectorStore != null,
                () -> deleteDecisionHistory(userId), purged, failed);
        for (UserStatePurgeContributor contributor : contributors) {
            step(contributor.name(), true, () -> contributor.purge(userId), purged, failed);
        }

        if (!failed.isEmpty()) {
            log.error("[UserEngineStatePurger] User state purge incomplete: userId={}, failedSteps={}",
                    userId, failed.keySet());
        }
        return new UserEngineStatePurgeResult(userId, purged, failed);
    }

    private void deleteDecisionHistory(String userId) {
        Filter.Expression userDocuments = new FilterExpressionBuilder().eq(RAG_USER_METADATA_KEY, userId).build();
        vectorStore.delete(VectorStoreFilterValues.encode(userDocuments, vectorStore));
    }

    private void step(String name, boolean available, Runnable action, List<String> purged, Map<String, String> failed) {
        if (!available) {
            return;
        }
        try {
            action.run();
            purged.add(name);
        } catch (RuntimeException e) {
            log.error("[UserEngineStatePurger] Purge step failed: step={}", name, e);
            failed.put(name, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
