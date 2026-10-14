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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeCollector;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

/**
 * Keeps a request that reached no analysis as a fact of its session (N-SES-1). A request answered by the decision
 * already in force for the user (an ALLOW still valid, a stored restriction, the request sent again after a passed
 * step-up) is not analysed, yet it is part of what the session did: later decisions read the session's narrative and
 * its decision history, and count what the session already exported under an approval from its allowed decisions.
 * The request's narrative step and its line in the session's decision history are recorded under the action applied
 * to it, once per request. Nothing is learned from it: the usual behaviour and the role scope learn from analysed
 * requests only. A request a web filter stops under the decision in force reaches no protected method; it is
 * recorded as the request it is.
 */
@Slf4j
public class UnanalysedRequestRecorder {

    private final SessionNarrativeCollector sessionNarrativeCollector;
    private final ContextObservationRecorder recorder;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final ZeroTrustEventPublisher zeroTrustEventPublisher;

    public UnanalysedRequestRecorder(SessionNarrativeCollector sessionNarrativeCollector,
                                     ContextObservationRecorder recorder,
                                     @Nullable SecurityZeroTrustProperties securityZeroTrustProperties,
                                     @Nullable ZeroTrustEventPublisher zeroTrustEventPublisher) {
        this.sessionNarrativeCollector = sessionNarrativeCollector;
        this.recorder = recorder;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
    }

    /**
     * Records the current request of an authenticated user that a web filter stopped under the action in force (a
     * stored CHALLENGE, BLOCK or ESCALATE): it reached no protected method and no analysis, yet the session made it.
     */
    public void recordRequest(Authentication authentication, ZeroTrustAction action) {
        if (authentication == null || zeroTrustEventPublisher == null || action == null
                || action == ZeroTrustAction.PENDING_ANALYSIS) {
            return;
        }
        try {
            record(zeroTrustEventPublisher.buildRequestAuthorizationEvent(authentication, false, action.name()), action);
        } catch (RuntimeException e) {
            log.error("Failed to record a request a filter stopped: userId={}", authentication.getName(), e);
        }
    }

    /**
     * Records the event's request under the action applied to it. A pending action means no decision is in force: the
     * request goes to analysis, which records it.
     */
    public void record(ZeroTrustSpringEvent event, ZeroTrustAction action) {
        if (event == null || action == null || action == ZeroTrustAction.PENDING_ANALYSIS) {
            return;
        }
        try {
            SecurityEvent securityEvent = ZeroTrustSecurityEventConverter.convert(event);
            if (recorder.committed(securityEvent)) {
                return;
            }
            sessionNarrativeCollector.collect(securityEvent);
            recorder.commit(securityEvent, action.name(), enforced(event));
        } catch (RuntimeException e) {
            log.error("Failed to record a request that was not analysed: userId={}", event.getUserId(), e);
        }
    }

    /** Whether the action in force is enforced on the request, as the enforcement of an analysed decision is. */
    private boolean enforced(ZeroTrustSpringEvent event) {
        if (securityZeroTrustProperties != null && !securityZeroTrustProperties.isEnforcementEnabled()) {
            return false;
        }
        Object boundary = event.getPayloadValue("decisionBoundaryMode");
        return boundary == null || !"SHADOW".equalsIgnoreCase(boundary.toString().trim());
    }
}
