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
import io.contexa.contexacore.autonomous.service.NewContextDecisionLimit;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ZeroTrustEventListener {

    private final SecurityEventPublisher securityEventPublisher;
    private final ZeroTrustActionRepository actionRepository;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private UnanalysedRequestRecorder unanalysedRequestRecorder;
    private NewContextDecisionLimit newContextDecisionLimit;

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

    /**
     * The decisions of a new context a person may ask for in a short window, which a person's sign-ins take from with
     * the calls of a changed context; without it every sign-in is analysed.
     */
    public void setNewContextDecisionLimit(NewContextDecisionLimit newContextDecisionLimit) {
        this.newContextDecisionLimit = newContextDecisionLimit;
    }

    @EventListener
    public void handleZeroTrustEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            // PR-21: as at a protected method, a mode that allows no analysis sends nothing to it: every event ends in a model call.
            if (!securityZeroTrustProperties.allowsLlmAnalysis()) {
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
        if (signInPastTheLimit(event)) {
            return;
        }
        securityEventPublisher.publishGenericSecurityEvent(event);
    }

    /**
     * A sign-in past the person's decisions of a new context in the window is not analysed: whoever signs in again and
     * again would buy a model decision with each. It goes on, as the sign-in itself is never refused; it is kept as a
     * fact of its session, and where decisions are enforced the person is asked to verify, the session the client
     * presents next among them, as a CHALLENGE asks every session. A stricter decision in force stays as it is.
     *
     * @return whether the sign-in was answered here instead of by an analysis
     */
    private boolean signInPastTheLimit(ZeroTrustSpringEvent event) {
        if (newContextDecisionLimit == null
                || !ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS.equals(event.getEventType())) {
            return false;
        }
        String key = decisionKey(event);
        if (key == null || key.isBlank()
                || newContextDecisionLimit.take(key, NewContextDecisionLimit.Kind.SIGN_IN)) {
            return false;
        }
        if (enforced(event)) {
            askToVerify(key, event);
        }
        if (unanalysedRequestRecorder != null) {
            unanalysedRequestRecorder.record(event, ZeroTrustAction.CHALLENGE);
        }
        return true;
    }

    private void askToVerify(String key, ZeroTrustSpringEvent event) {
        Map<String, Object> fields = new HashMap<>();
        Object context = event.getPayloadValue("contextBindingHash");
        if (context != null && !context.toString().isBlank()) {
            fields.put("contextBindingHash", context.toString());
        }
        fields.put("reasoning", "The person's sign-ins passed the decisions of a new context allowed in a short "
                + "window; this sign-in went on undecided and the person is asked to verify.");
        fields.put(ZeroTrustActionRepository.LLM_DECISION_PRESENT, false);
        try {
            ZeroTrustActionRepository.FinalActionWrite written = actionRepository.writeUndecidedChallenge(key, fields);
            if (written == ZeroTrustActionRepository.FinalActionWrite.FAILED) {
                log.error("[ZeroTrustEventListener] The verification asked of a sign-in past the decision limit could "
                        + "not be stored: userId={}", key);
            }
        } catch (RuntimeException e) {
            log.error("[ZeroTrustEventListener] The verification asked of a sign-in past the decision limit could not "
                    + "be stored: userId={}", key, e);
        }
    }

    /** Whether decisions are enforced on the event, as the enforcement of an analysed decision would be. */
    private boolean enforced(ZeroTrustSpringEvent event) {
        if (!securityZeroTrustProperties.isEnforcementEnabled()) {
            return false;
        }
        Object boundary = event.getPayloadValue("decisionBoundaryMode");
        return boundary == null || !"SHADOW".equalsIgnoreCase(boundary.toString().trim());
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
