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
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SynchronousProtectableDecisionServiceTest {

    private static final String USER_ID = "alice";
    private static final String CONTEXT_HASH = "ctx-hash";

    @Mock
    private ZeroTrustEventPublisher eventPublisher;

    @Mock
    private ZeroTrustEventListener eventListener;

    @Mock
    private SecurityPlaneAgent securityPlaneAgent;

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private MethodInvocation methodInvocation;

    private UsernamePasswordAuthenticationToken authentication;
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        authentication = new UsernamePasswordAuthenticationToken(USER_ID, "n/a", List.of());
        service = new SynchronousProtectableDecisionService(
                eventPublisher,
                eventListener,
                securityPlaneAgent,
                actionRepository);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("sync Protectable executes one LLM decision")
    void analyze_noPreAnalysis_shouldProcessLlmEvent() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class)))
                .thenReturn(mock(SecurityEventContext.class));

        service.analyze(methodInvocation, authentication);

        verify(securityPlaneAgent).processSecurityEvent(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("sync decision should use final action when proposed action is absent")
    void analyze_processingResultWithoutProposedAction_shouldUseFinalAction() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        ProcessingResult processingResult = ProcessingResult.builder()
                .action(ZeroTrustAction.CHALLENGE.name())
                .build();
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult", processingResult));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        SynchronousProtectableDecisionService.SyncDecisionResult result =
                service.analyze(methodInvocation, authentication);

        assertThat(result.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("sync decision should enforce constrained final action instead of proposed action")
    void analyze_constrainedProcessingResult_shouldUseFinalAction() {
        MockHttpServletRequest request = request("/admin/reports");
        bindRequest(request);
        ZeroTrustSpringEvent event = methodEvent("/admin/reports");
        stubEvent(event);
        ProcessingResult processingResult = ProcessingResult.builder()
                .action(ZeroTrustAction.CHALLENGE.name())
                .proposedAction(ZeroTrustAction.ALLOW.name())
                .autonomyConstraintApplied(true)
                .build();
        SecurityEventContext processingContext = mock(SecurityEventContext.class);
        when(processingContext.getMetadata()).thenReturn(Map.of("processingResult", processingResult));
        when(securityPlaneAgent.processSecurityEvent(any(SecurityEvent.class))).thenReturn(processingContext);

        SynchronousProtectableDecisionService.SyncDecisionResult result =
                service.analyze(methodInvocation, authentication);

        assertThat(result.action()).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    private void stubEvent(ZeroTrustSpringEvent event) {
        when(eventPublisher.buildMethodAuthorizationEvent(methodInvocation, authentication, true, null))
                .thenReturn(event);
        when(eventListener.generateAuthorizationContextBindingHash(event)).thenReturn(CONTEXT_HASH);
        when(eventListener.shouldPublishAuthorizationEvent(event)).thenReturn(true);
        lenient().when(actionRepository.getCurrentAction(USER_ID, CONTEXT_HASH)).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(actionRepository.getAnalysisData(USER_ID)).thenReturn(ZeroTrustActionRepository.ZeroTrustAnalysisData.pending());
    }

    private ZeroTrustSpringEvent methodEvent(String path) {
        return ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER_ID)
                .sessionId("session-1")
                .clientIp("203.0.113.10")
                .userAgent("JUnit")
                .resource(path)
                .payload(Map.of(
                        "httpMethod", "GET",
                        "requestPath", path))
                .build();
    }

    private MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("User-Agent", "JUnit");
        return request;
    }

    private void bindRequest(MockHttpServletRequest request) {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
