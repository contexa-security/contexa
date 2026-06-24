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
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyKeyFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class SynchronousProtectableDecisionService {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final ZeroTrustEventListener zeroTrustEventListener;
    private final SecurityPlaneAgent securityPlaneAgent;
    private final ZeroTrustActionRepository actionRepository;
    private final AnalysisTriggerStateRepository analysisTriggerStateRepository;
    private final Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier;

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
        this(zeroTrustEventPublisher, zeroTrustEventListener, securityPlaneAgent, actionRepository,
                analysisTriggerStateRepository, null);
    }

    public SynchronousProtectableDecisionService(
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustEventListener zeroTrustEventListener,
            SecurityPlaneAgent securityPlaneAgent,
            ZeroTrustActionRepository actionRepository,
            AnalysisTriggerStateRepository analysisTriggerStateRepository,
            Supplier<AiSecurityDecisionObservationWriter> aiSecurityDecisionObservationWriterSupplier) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
        this.zeroTrustEventListener = zeroTrustEventListener;
        this.securityPlaneAgent = securityPlaneAgent;
        this.actionRepository = actionRepository;
        this.analysisTriggerStateRepository = analysisTriggerStateRepository;
        this.aiSecurityDecisionObservationWriterSupplier = aiSecurityDecisionObservationWriterSupplier == null
                ? () -> null
                : aiSecurityDecisionObservationWriterSupplier;
    }

    public SyncDecisionResult analyze(MethodInvocation methodInvocation, Authentication authentication) {
        ZeroTrustSpringEvent event = zeroTrustEventPublisher.buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                true,
                null
        );
        markProtectableAnalysisStarted();

        String userId = event.getUserId();
        String contextBindingHash = zeroTrustEventListener.generateAuthorizationContextBindingHash(event);

        if (zeroTrustEventListener.shouldPublishAuthorizationEvent(event)) {
            if (isPreProtectableAnalysisAlreadyStarted(event, contextBindingHash)) {
                scheduleProtectableMerge(event);
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
        if (processingResult == null && isCurrentRequestPreTriggerShadow()) {
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
        ZeroTrustAction proposedAction = ZeroTrustAction.fromString(processingResult.getProposedAction());
        if (proposedAction != null) {
            return proposedAction;
        }
        return ZeroTrustAction.fromString(processingResult.getAction());
    }

    private boolean isEventShadowBoundary(ZeroTrustSpringEvent event) {
        if (event == null || event.getPayload() == null) {
            return false;
        }
        return "SHADOW".equalsIgnoreCase(firstText(event.getPayload().get("decisionBoundaryMode")));
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

    private boolean isCurrentRequestPreTriggerShadow() {
        Object mode = currentRequestAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DECISION_BOUNDARY_MODE);
        return "SHADOW".equalsIgnoreCase(firstText(mode));
    }

    private Object currentRequestAttribute(String attributeName) {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return null;
            }
            return attrs.getRequest().getAttribute(attributeName);
        } catch (Exception e) {
            return null;
        }
    }

    private void scheduleProtectableMerge(ZeroTrustSpringEvent event) {
        String evaluationId = firstText(
                currentRequestAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_MERGE_EVALUATION_ID),
                currentRequestAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID));
        AiSecurityDecisionObservationWriter writer = aiSecurityDecisionObservationWriterSupplier.get();
        if (!StringUtils.hasText(evaluationId) || writer == null) {
            return;
        }
        Map<String, Object> payload = event != null && event.getPayload() != null ? event.getPayload() : Map.of();
        String resourceId = firstText(
                payload.get("protectableResourceId"),
                payload.get("resourceId"),
                payload.get("requestedResourceId"),
                payload.get("protectedResourceId"));
        String resourceUrl = firstText(
                payload.get("protectableResourceUrl"),
                payload.get("requestPath"),
                payload.get("requestUri"),
                event != null ? event.getResource() : null,
                currentRequestNormalizedPath());
        String httpMethod = firstText(
                payload.get("protectableHttpMethod"),
                payload.get("httpMethod"),
                payload.get("method"));

        CompletableFuture.runAsync(() -> {
            for (int attempt = 0; attempt < 60; attempt++) {
                if (writer.markProtectableMerged(evaluationId, resourceId, resourceUrl, httpMethod)) {
                    return;
                }
                try {
                    Thread.sleep(100L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
    }

    private void markProtectableAnalysisStarted() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                attrs.getRequest().setAttribute(PendingAnomalyTriggerAttributes.PROTECTABLE_TRIGGER_STARTED, true);
            }
        } catch (Exception e) {
            // Best effort only. Distributed suppression still uses the shared state repository.
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
