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
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import lombok.RequiredArgsConstructor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;

@RequiredArgsConstructor
public class SynchronousProtectableDecisionService {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustEventListener zeroTrustEventListener;
    private final SecurityPlaneAgent securityPlaneAgent;
    private final ZeroTrustActionRepository actionRepository;

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
            return new SyncDecisionResult(
                    event,
                    contextBindingHash,
                    actionRepository.getCurrentAction(userId, contextBindingHash),
                    actionRepository.getAnalysisData(userId),
                    processingContext
            );
        }

        return new SyncDecisionResult(
                event,
                contextBindingHash,
                actionRepository.getCurrentAction(userId, contextBindingHash),
                actionRepository.getAnalysisData(userId),
                null
        );
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
