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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public class SynchronousProtectableDecisionService {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustEventListener zeroTrustEventListener;
    private final SecurityPlaneAgent securityPlaneAgent;
    private final ZeroTrustActionRepository actionRepository;

    public SynchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.zeroTrustEventListener = zeroTrustEventListener;
        this.securityPlaneAgent = securityPlaneAgent;
        this.actionRepository = actionRepository;
    }

    public SyncDecisionResult analyze(MethodInvocation methodInvocation, Authentication authentication) {
        ZeroTrustSpringEvent event = zeroTrustEventPublisher.buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                true,
                null
        );
        String userId = event.getUserId();
        String contextBindingHash = zeroTrustEventListener.generateAuthorizationContextBindingHash(event);

        if (zeroTrustEventListener.shouldPublishAuthorizationEvent(event)) {
            SecurityEvent securityEvent = ZeroTrustSecurityEventConverter.convert(event);
            SecurityEventContext processingContext = securityPlaneAgent.processSecurityEvent(securityEvent);
            return currentResult(event, userId, contextBindingHash, processingContext);
        }

        return currentResult(event, userId, contextBindingHash, null);
    }

    private SyncDecisionResult currentResult(
            ZeroTrustSpringEvent event,
            String userId,
            String contextBindingHash,
            SecurityEventContext processingContext) {
        return new SyncDecisionResult(
                event,
                contextBindingHash,
                resolveSynchronousAction(event, userId, contextBindingHash, processingContext),
                actionRepository.getAnalysisData(userId),
                processingContext
        );
    }

    private ZeroTrustAction resolveSynchronousAction(
            ZeroTrustSpringEvent event,
            String userId,
            String contextBindingHash,
            SecurityEventContext processingContext) {
        ProcessingResult processingResult = processingResult(processingContext);
        if (processingResult != null && isEventShadowBoundary(event)) {
            return ZeroTrustAction.ALLOW;
        }
        ZeroTrustAction processingAction = processingAction(processingResult);
        if (processingAction != null) {
            return processingAction;
        }
        return actionRepository.getCurrentAction(userId, contextBindingHash);
    }

    private ProcessingResult processingResult(SecurityEventContext processingContext) {
        if (processingContext == null || processingContext.getMetadata() == null) {
            return null;
        }
        Object result = processingContext.getMetadata().get("processingResult");
        return result instanceof ProcessingResult processingResult ? processingResult : null;
    }

    private ZeroTrustAction processingAction(ProcessingResult processingResult) {
        if (processingResult == null) {
            return null;
        }
        // The final action includes autonomy constraints and technical fallbacks and is
        // therefore the action that synchronous enforcement must apply. proposedAction
        // is retained for audit purposes only.
        if (StringUtils.hasText(processingResult.getAction())) {
            return ZeroTrustAction.fromString(processingResult.getAction());
        }
        if (StringUtils.hasText(processingResult.getProposedAction())) {
            return ZeroTrustAction.fromString(processingResult.getProposedAction());
        }
        return null;
    }

    private boolean isEventShadowBoundary(ZeroTrustSpringEvent event) {
        if (event == null || event.getPayload() == null) {
            return false;
        }
        return "SHADOW".equalsIgnoreCase(firstText(event.getPayload().get("decisionBoundaryMode")));
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString().trim();
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    public record SyncDecisionResult(
            ZeroTrustSpringEvent event,
            String contextBindingHash,
            ZeroTrustAction action,
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysisData,
            SecurityEventContext processingContext
    ) {
    }
}
