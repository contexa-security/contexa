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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * What a completed step-up changes in the decision store: a CHALLENGE becomes ALLOW for the session that answered it and
 * stays in force for the user's other sessions (Q-12), the challenged request is learned as normal behaviour, the user
 * is marked as verified, a BLOCK an administrator let the user release by MFA is released. It is the same under both
 * ownerships: Contexa's MFA completion (CONTEXA_OWNED) and the verification-only step-up (HOST_OWNED) call it, and only
 * CONTEXA_OWNED also stores a new authentication for the user.
 */
@Slf4j
public class ChallengeResolution {

    private final ZeroTrustActionRepository actionRepository;
    private final SecurityLearningService securityLearningService;
    private final Supplier<VerificationLearningService> verificationLearningService;
    private final Supplier<SecurityContextDataStore> securityContextDataStore;
    private final BlockingSignalBroadcaster blockingSignalBroadcaster;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final BlockMfaStateStore blockMfaStateStore;

    public ChallengeResolution(ZeroTrustActionRepository actionRepository,
                               SecurityLearningService securityLearningService,
                               Supplier<VerificationLearningService> verificationLearningService,
                               Supplier<SecurityContextDataStore> securityContextDataStore,
                               BlockingSignalBroadcaster blockingSignalBroadcaster,
                               IBlockedUserRecorder blockedUserRecorder,
                               BlockMfaStateStore blockMfaStateStore) {
        this.actionRepository = actionRepository;
        this.securityLearningService = securityLearningService;
        this.verificationLearningService = verificationLearningService != null ? verificationLearningService : () -> null;
        this.securityContextDataStore = securityContextDataStore != null ? securityContextDataStore : () -> null;
        this.blockingSignalBroadcaster = blockingSignalBroadcaster;
        this.blockedUserRecorder = blockedUserRecorder;
        this.blockMfaStateStore = blockMfaStateStore;
    }

    /** Records that the user passed a step-up at the given time (the engine reads it as a fact of later requests). */
    public void markMfaVerified(String userId, @Nullable Instant verifiedAt) {
        try {
            SecurityContextDataStore dataStore = securityContextDataStore.get();
            if (dataStore != null) {
                dataStore.markMfaVerified(userId, verifiedAt);
            }
        } catch (Exception e) {
            log.error("[MFA] Failed to mark MFA verified on challenge success: userId={}", userId, e);
        }
    }

    /**
     * Releases the CHALLENGE in force for the decision key in the given context, and no other: it becomes ALLOW bound to
     * that context, the user's other sessions keep it until they answer it themselves (Q-12), and the request it stopped
     * is learned as normal behaviour. A session a CHALLENGE answered elsewhere still holds is released the same way, with
     * nothing to learn: its request was learned when the CHALLENGE was first answered. An ESCALATE waits for a review and
     * is not lifted by a verification of the user (Q-87, N-P3-1); nothing changes then and false is returned. Otherwise
     * the unblock signal goes out and true is returned. An answer that cannot be kept to its session releases no one.
     *
     * @param contextBindingHash the context the ALLOW is bound to: the one the client uses next
     * @param originalIp         the address the challenged sign-in came from, when known
     */
    public boolean releaseChallenge(String userId, String contextBindingHash, HttpServletRequest request,
                                    @Nullable String originalIp) {
        if (userId == null || userId.isBlank() || actionRepository == null) {
            return false;
        }
        try {
            ZeroTrustAction currentAction = actionRepository.getActionFromHash(userId);
            if (currentAction == ZeroTrustAction.ESCALATE) {
                return false;
            }
            if (currentAction == ZeroTrustAction.CHALLENGE) {
                // The request the challenge stopped, read before the ALLOW replaces the decision that names it (W5-2).
                String challengedRequestId = challengedRequestId(userId);
                actionRepository.holdChallengeForOtherSessions(userId, contextBindingHash);
                actionRepository.saveActionWithPrevious(userId, ZeroTrustAction.ALLOW, contextBindingHash);
                learnStepUp(userId, request, originalIp, challengedRequestId);
            } else if (actionRepository.getCurrentAction(userId, contextBindingHash) == ZeroTrustAction.CHALLENGE) {
                actionRepository.holdChallengeForOtherSessions(userId, contextBindingHash);
                actionRepository.saveActionWithPrevious(userId, ZeroTrustAction.ALLOW, contextBindingHash);
            }
            keepAsAFactOfTheContext(userId, contextBindingHash, request);
            if (blockingSignalBroadcaster != null) {
                blockingSignalBroadcaster.registerUnblock(userId);
            }
            return true;
        } catch (Exception e) {
            log.error("[MFA] Failed to set action to ALLOW for user: {}", userId, e);
            return false;
        }
    }

    /**
     * Q-16: the decisions after the step-up are told of it. It is kept for the context the client goes on in, so that
     * the session that passed it reads as verified and another session of the user does not.
     */
    private void keepAsAFactOfTheContext(String userId, String contextBindingHash, HttpServletRequest request) {
        try {
            SecurityContextDataStore dataStore = securityContextDataStore.get();
            if (dataStore != null) {
                Instant observedAt = RequestInfoExtractor.extractObservedAt(request);
                dataStore.markChallengeVerified(userId, contextBindingHash,
                        observedAt != null ? observedAt : Instant.now());
            }
        } catch (Exception e) {
            log.error("[MFA] Failed to keep the passed step-up as a fact of its context: userId={}", userId, e);
        }
    }

    /** Releases a BLOCK an administrator let the user release by MFA. */
    public void releaseBlockByMfa(String userId) {
        releaseBlockByMfa(userId, null);
    }

    /**
     * Releases a BLOCK an administrator let the user release by MFA, and keeps the verification for the context that
     * passed it: an administrator lifts their own BLOCK in that session and in no other of the account.
     *
     * @param contextBindingHash the context the client goes on in, or null to name none
     */
    public void releaseBlockByMfa(String userId, @Nullable String contextBindingHash) {
        try {
            if (blockedUserRecorder != null) {
                blockedUserRecorder.markMfaVerified(userId);
            }
            if (blockMfaStateStore != null) {
                blockMfaStateStore.setVerified(userId, contextBindingHash);
                blockMfaStateStore.clearPending(userId);
            }
            if (blockingSignalBroadcaster != null) {
                blockingSignalBroadcaster.registerUnblock(userId);
            }
        } catch (Exception e) {
            log.error("[MFA] Failed to process block MFA success for user: {}", userId, e);
        }
    }

    @Nullable
    private String challengedRequestId(String userId) {
        try {
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = actionRepository.getAnalysisData(userId);
            return analysis != null ? analysis.requestId() : null;
        } catch (Exception e) {
            log.error("[MFA] Failed to read the challenged request of user: {}", userId, e);
            return null;
        }
    }

    /**
     * Learns the request the challenge stopped from its own facts at a reduced weight (W5-2). Without kept facts the
     * step-up is learned as before, from the step-up request.
     */
    private void learnStepUp(String userId, HttpServletRequest request, @Nullable String originalIp,
                             @Nullable String challengedRequestId) {
        VerificationLearningService verificationLearning = verificationLearningService.get();
        if (verificationLearning != null && verificationLearning.learnStepUp(userId, challengedRequestId)) {
            return;
        }
        if (securityLearningService == null) {
            return;
        }
        try {
            String effectiveIp = (originalIp != null && !originalIp.isBlank())
                    ? originalIp : SessionFingerprintUtil.extractClientIp(request);

            SecurityDecision decision = SecurityDecision.builder()
                    .action(ZeroTrustAction.ALLOW)
                    .confidence(0.95)
                    .riskScore(0.05)
                    .reasoning("LLM-challenged MFA completed - verified as normal behavior")
                    .analysisTime(System.currentTimeMillis())
                    .build();

            Instant observedAt = RequestInfoExtractor.extractObservedAt(request);
            SecurityEvent event = SecurityEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .source(SecurityEvent.EventSource.IAM)
                    .userId(userId)
                    .sourceIp(effectiveIp)
                    .sessionId(request.getSession(false) != null ? request.getSession(false).getId() : null)
                    .userAgent(request.getHeader("User-Agent"))
                    .timestamp(observedAt != null ? observedAt : Instant.now())
                    .description("LLM-challenged MFA success - learning")
                    .build();
            // The baseline is kept under the request's tenant (W5-10 D9).
            String tenantId = RequestInfoExtractor.extractTenantId(request);
            if (tenantId != null) {
                event.addMetadata("tenantId", tenantId);
            }

            securityLearningService.learnAndStore(userId, decision, event);
        } catch (Exception e) {
            log.error("[MFA] Failed to learn on LLM-challenged MFA success: userId={}", userId, e);
        }
    }
}
