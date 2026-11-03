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
package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

@Slf4j
public class ZeroTrustEventListener {

    private final SecurityEventPublisher securityEventPublisher;
    private final ZeroTrustActionRepository actionRepository;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private UnanalysedRequestRecorder unanalysedRequestRecorder;

    public ZeroTrustEventListener(
            SecurityEventPublisher securityEventPublisher,
            ZeroTrustActionRepository actionRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.securityEventPublisher = securityEventPublisher;
        this.actionRepository = actionRepository;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    public void setUnanalysedRequestRecorder(UnanalysedRequestRecorder unanalysedRequestRecorder) {
        this.unanalysedRequestRecorder = unanalysedRequestRecorder;
    }

    @EventListener
    public void handleZeroTrustEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            if (!securityZeroTrustProperties.isEnabled()) {
                return;
            }

            switch (event.getCategory()) {
                case AUTHENTICATION:
                    processAuthenticationEvent(event);
                    break;
                case AUTHORIZATION:
                    processAuthorizationEvent(event);
                    break;
                case SESSION:
                    processSessionEvent(event);
                    break;
                case THREAT:
                    processThreatEvent(event);
                    break;
                case CUSTOM:
                    processCustomEvent(event);
                    break;
                default:
                    log.error("[ZeroTrustEventListener] Unhandled event category: {}", event.getCategory());
            }

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[ZeroTrustEventListener] Failed to process event - category: {}, type: {}, duration: {}ms",
                    event.getCategory(), event.getEventType(), duration, e);
        }
    }

    public boolean shouldPublishAuthorizationEvent(ZeroTrustSpringEvent event) {
        if (event == null) {
            return false;
        }
        if (event.getCategory() != null && event.getCategory().name().equals("AUTHORIZATION")) {
            return !shouldSkipPublishing(event, generateAuthorizationContextBindingHash(event), true);
        }
        return true;
    }

    /**
     * Whether a synchronous {@code @Protectable} request is analysed. Unlike an asynchronous one, an ALLOW in force
     * for its session does not answer it: the application protected the operation synchronously so that it is decided
     * before it runs, and an ALLOW of an earlier request of the session (a document read seconds before) says nothing
     * about it. A business agent sends its requests seconds apart, inside an ALLOW's validity (docs/agent A7-2, real
     * server 2026-10-23). A restriction in force (BLOCK, CHALLENGE, ESCALATE) still answers it, as does a decision of
     * the same context that waits for its audit record.
     */
    public boolean shouldPublishSynchronousAuthorizationEvent(ZeroTrustSpringEvent event) {
        if (event == null) {
            return false;
        }
        if (event.getCategory() != null && event.getCategory().name().equals("AUTHORIZATION")) {
            return !shouldSkipPublishing(event, generateAuthorizationContextBindingHash(event), false);
        }
        return true;
    }

    public String generateAuthorizationContextBindingHash(ZeroTrustSpringEvent event) {
        if (event == null) {
            return null;
        }
        Object existing = event.getPayloadValue("contextBindingHash");
        if (existing != null && !existing.toString().isBlank()) {
            return existing.toString();
        }
        return SessionFingerprintUtil.generateContextBindingHash(
                event.getSessionId(),
                event.getClientIp(),
                event.getUserAgent()
        );
    }

    private void processAuthenticationEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processAuthorizationEvent(ZeroTrustSpringEvent event) {
        if (!shouldPublishAuthorizationEvent(event)) {
            recordUnanalysed(event);
            return;
        }
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * docs/agent A5-1: the key the request's decision is read under: an agent acting for a person reads its own
     * decisions, everyone else the user ID's.
     */
    private static String decisionKey(ZeroTrustSpringEvent event) {
        ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(event.getUserId(), event.getPayload());
        return subject != null ? subject.storageKey() : event.getUserId();
    }

    /** A request answered by the decision in force reaches no analysis; its session still keeps it (N-SES-1). */
    private void recordUnanalysed(ZeroTrustSpringEvent event) {
        String userId = decisionKey(event);
        if (unanalysedRequestRecorder == null || userId == null || userId.isBlank()) {
            return;
        }
        try {
            unanalysedRequestRecorder.record(event,
                    actionRepository.getCurrentAction(userId, generateAuthorizationContextBindingHash(event)));
        } catch (Exception e) {
            log.error("[ZeroTrustEventListener] Failed to record a request that was not analysed: userId={}", userId, e);
        }
    }

    private void processSessionEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processThreatEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    private void processCustomEvent(ZeroTrustSpringEvent event) {
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * Whether the request is answered by the decision in force instead of an analysis.
     *
     * @param allowAnswers whether an ALLOW in force answers the request without analysis
     */
    private boolean shouldSkipPublishing(ZeroTrustSpringEvent event, String contextBindingHash, boolean allowAnswers) {
        String key = decisionKey(event);
        if (key == null || key.isBlank()) {
            return false;
        }

        try {
            // docs/agent A5-1: read through the request's subject, so that an agent acting for a person is also
            // answered by the person's BLOCK (finding F-5: a synchronous request of the agent was analysed in place
            // and let through while the person was blocked).
            ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(event.getUserId(), event.getPayload());
            ZeroTrustAction currentAction = subject != null
                    ? subject.currentAction(actionRepository, contextBindingHash)
                    : actionRepository.getCurrentAction(key, contextBindingHash);
            if (currentAction != ZeroTrustAction.PENDING_ANALYSIS
                    && (allowAnswers || currentAction != ZeroTrustAction.ALLOW)) {
                return true;
            }
            // A decision for this actor context is waiting for its audit record; a new analysis
            // would only repeat the LLM call while the observation store keeps rejecting writes.
            return actionRepository.isDecisionAuditPending(key, contextBindingHash);
        } catch (Exception e) {
            log.error("[ZeroTrustEventListener] Failed to check skip condition: userId={}", key, e);
            return false;
        }
    }
}
