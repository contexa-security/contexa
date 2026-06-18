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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyKeyFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class SynchronousProtectableDecisionService {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustEventListener zeroTrustEventListener;
    private final SecurityPlaneAgent securityPlaneAgent;
    private final ZeroTrustActionRepository actionRepository;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;

    public SynchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository) {
        this(zeroTrustEventPublisher, zeroTrustEventListener, securityPlaneAgent, actionRepository, null);
    }

    public SynchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository,
            AnalysisTriggerStateRepository analysisTriggerStateRepository) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.zeroTrustEventListener = zeroTrustEventListener;
        this.securityPlaneAgent = securityPlaneAgent;
        this.actionRepository = actionRepository;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
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
            if (isPreProtectableAnalysisAlreadyStarted(event, contextBindingHash)) {
                return currentResult(event, userId, contextBindingHash, null);
            }
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
                actionRepository.getCurrentAction(userId, contextBindingHash),
                actionRepository.getAnalysisData(userId),
                processingContext
        );
    }

    private boolean isPreProtectableAnalysisAlreadyStarted(
            ZeroTrustSpringEvent event,
            String contextBindingHash) {
        if (sameRequestPreTriggerStarted()) {
            return true;
        }
        if (analysisTriggerStateRepository == null || event == null || event.getPayload() == null) {
            return false;
        }
        String stateKey = buildSharedStateKey(event, contextBindingHash);
        if (!StringUtils.hasText(stateKey)) {
            return false;
        }
        return analysisTriggerStateRepository.isInFlight(stateKey)
                || analysisTriggerStateRepository.isCoolingDown(stateKey);
    }

    private boolean sameRequestPreTriggerStarted() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return false;
            }
            HttpServletRequest request = attrs.getRequest();
            return Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED));
        } catch (Exception e) {
            return false;
        }
    }

    private String buildSharedStateKey(ZeroTrustSpringEvent event, String contextBindingHash) {
        String userId = event.getUserId();
        String method = firstText(event.getPayload().get("httpMethod"));
        String path = firstText(
                currentRequestNormalizedPath(),
                event.getPayload().get("requestPath"),
                event.getPayload().get("requestUri"),
                event.getResource());
        if (!StringUtils.hasText(userId)
                || !StringUtils.hasText(contextBindingHash)
                || !StringUtils.hasText(method)
                || !StringUtils.hasText(path)) {
            return null;
        }
        return PendingAnomalyKeyFactory.buildBaseKey(
                userId,
                contextBindingHash,
                method,
                HcadRequestPathUtils.normalizePathText(path));
    }

    private String currentRequestNormalizedPath() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return null;
            }
            return HcadRequestPathUtils.normalizedPath(attrs.getRequest());
        } catch (Exception e) {
            return null;
        }
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
