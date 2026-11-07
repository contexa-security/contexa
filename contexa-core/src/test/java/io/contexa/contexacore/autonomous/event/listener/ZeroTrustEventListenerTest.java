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

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ZeroTrustEventListenerTest {

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private SecurityZeroTrustProperties securityZeroTrustProperties;

    private ZeroTrustEventListener listener;

    @BeforeEach
    void setUp() {
        listener = new ZeroTrustEventListener(
                securityEventPublisher, actionRepository, securityZeroTrustProperties);
        when(securityZeroTrustProperties.allowsLlmAnalysis()).thenReturn(true);
    }

    @Test
    @DisplayName("a second-factor AUTHENTICATION event should invoke publishGenericSecurityEvent")
    void authenticationEvent_shouldPublish() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_MFA)
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("10.0.0.1")
                .build();

        // when
        listener.handleZeroTrustEvent(event);

        // then
        verify(securityEventPublisher).publishGenericSecurityEvent(event);
    }

    @Test
    @DisplayName("a person's sign-in is not sent to the analysis: the first call to a protected resource is decided")
    void aSignInIsNotSentToTheAnalysis() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS)
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("10.0.0.1")
                .build();

        listener.handleZeroTrustEvent(event);

        verify(securityEventPublisher, never()).publishGenericSecurityEvent(any());
    }

    @Test
    @DisplayName("AUTHORIZATION event should apply duplicate filtering logic")
    void authorizationEvent_shouldApplyDuplicateFiltering() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-2")
                .sessionId("session-2")
                .clientIp("10.0.0.2")
                .userAgent("TestAgent")
                .build();

        when(actionRepository.getCurrentAction(anyString(), anyString()))
                .thenReturn(ZeroTrustAction.ALLOW);

        // when
        listener.handleZeroTrustEvent(event);

        // then - ALLOW action means shouldSkipPublishing returns true
        verify(securityEventPublisher, never()).publishGenericSecurityEvent(event);
    }

    /**
     * R4-L3: a request path and a scenario are the client's own text, so an authorization event that names the former
     * verification probe path or scenario is filtered like any other; nothing in it forces an analysis.
     */
    @Test
    @DisplayName("docs/agent A5-1: an agent acting for the user is answered by its own decision, not the user's")
    void anAgentsRequestIsAnsweredByTheAgentsOwnDecision() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("alice")
                .sessionId("agent:delegation:abc")
                .clientIp("10.60.1.43")
                .userAgent("report-agent/1.0")
                .payload(new HashMap<>(Map.of("executionSubjectKind", "DELEGATED_AGENT", "agentId", "report-agent",
                        "contextBindingHash", "ctx-agent")))
                .build();
        when(actionRepository.getCurrentAction("alice", "ctx-agent")).thenReturn(ZeroTrustAction.ALLOW);
        when(actionRepository.getCurrentAction("alice::agent::report-agent", "ctx-agent"))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(listener.shouldPublishAuthorizationEvent(event))
                .as("the person's ALLOW does not answer the agent's request").isTrue();

        when(actionRepository.getCurrentAction("alice::agent::report-agent", "ctx-agent"))
                .thenReturn(ZeroTrustAction.ALLOW);
        assertThat(listener.shouldPublishAuthorizationEvent(event)).isFalse();
    }

    /**
     * docs/agent A5-1 (ZeroTrustSubject): the person's BLOCK stops an agent acting for the person. A synchronous request
     * of the agent with no decision of its own was analysed in place and let through by the analysis while the person
     * was blocked (ownership harness 2026-11-03, finding F-5); the BLOCK in force answers it instead, as it does an
     * asynchronous one.
     */
    @Test
    @DisplayName("the person's BLOCK answers an agent's synchronous and asynchronous requests without analysis")
    void thePersonsBlockAnswersTheAgentsRequests() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("alice")
                .sessionId("agent:delegation:abc")
                .clientIp("10.60.1.43")
                .userAgent("report-agent/1.0")
                .payload(new HashMap<>(Map.of("executionSubjectKind", "DELEGATED_AGENT", "agentId", "report-agent",
                        "contextBindingHash", "ctx-agent")))
                .build();
        when(actionRepository.getCurrentAction("alice::agent::report-agent", "ctx-agent"))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(actionRepository.getCurrentAction("alice")).thenReturn(ZeroTrustAction.BLOCK);

        assertThat(listener.shouldPublishSynchronousAuthorizationEvent(event))
                .as("a synchronous request of the agent is answered by the person's BLOCK").isFalse();
        assertThat(listener.shouldPublishAuthorizationEvent(event))
                .as("an asynchronous request of the agent is answered by the person's BLOCK").isFalse();
    }

    @Test
    void anAuthorizationEventNamingTheProbePathIsFilteredLikeAnyOther() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-probe")
                .sessionId("session-probe")
                .clientIp("10.0.0.9")
                .userAgent("TestAgent")
                .payload(new HashMap<>(Map.of(
                        "requestPath", "/shop/admin/api/enterprise/verification/runtime/probe/normal/1",
                        "scenario", "OFFICIAL_VERIFICATION_RUNTIME")))
                .build();
        when(actionRepository.getCurrentAction(anyString(), anyString())).thenReturn(ZeroTrustAction.ALLOW);

        listener.handleZeroTrustEvent(event);

        verify(securityEventPublisher, never()).publishGenericSecurityEvent(event);
    }

    @Test
    @DisplayName("shouldPublishAuthorizationEvent with PENDING_ANALYSIS should return true")
    void shouldPublishAuthorizationEvent_pendingAnalysis_shouldReturnTrue() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-3")
                .sessionId("session-3")
                .clientIp("10.0.0.3")
                .build();

        when(actionRepository.getCurrentAction(anyString(), any()))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        // when
        boolean shouldPublish = listener.shouldPublishAuthorizationEvent(event);

        // then
        assertThat(shouldPublish).isTrue();
    }

    @Test
    @DisplayName("shouldPublishAuthorizationEvent with non-PENDING action should skip")
    void shouldPublishAuthorizationEvent_nonPendingAction_shouldSkip() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-4")
                .sessionId("session-4")
                .clientIp("10.0.0.4")
                .build();

        when(actionRepository.getCurrentAction(anyString(), any()))
                .thenReturn(ZeroTrustAction.BLOCK);

        // when
        boolean shouldPublish = listener.shouldPublishAuthorizationEvent(event);

        // then
        assertThat(shouldPublish).isFalse();
    }

    /**
     * docs/agent A7-2 (2026-10-23, user approval): an ALLOW in force answers an asynchronous request of its session
     * without analysis (N-SES-1) but not a synchronous one, which is decided itself; a restriction in force answers
     * both, and a decision waiting for its audit record is not asked again for either.
     */
    @Test
    @DisplayName("an ALLOW in force answers an asynchronous request, not a synchronous one")
    void allowInForce_answersAsynchronousRequestsOnly() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-agent-burst")
                .sessionId("session-agent-burst")
                .clientIp("10.60.1.42")
                .userAgent("report-agent/1.0")
                .build();
        String contextBindingHash = listener.generateAuthorizationContextBindingHash(event);

        when(actionRepository.getCurrentAction("user-agent-burst", contextBindingHash)).thenReturn(ZeroTrustAction.ALLOW);
        assertThat(listener.shouldPublishAuthorizationEvent(event)).isFalse();
        assertThat(listener.shouldPublishSynchronousAuthorizationEvent(event)).isTrue();

        when(actionRepository.isDecisionAuditPending("user-agent-burst", contextBindingHash)).thenReturn(true);
        assertThat(listener.shouldPublishSynchronousAuthorizationEvent(event)).isFalse();
        when(actionRepository.isDecisionAuditPending("user-agent-burst", contextBindingHash)).thenReturn(false);

        for (ZeroTrustAction restriction : new ZeroTrustAction[] {ZeroTrustAction.BLOCK, ZeroTrustAction.CHALLENGE,
                ZeroTrustAction.ESCALATE}) {
            when(actionRepository.getCurrentAction("user-agent-burst", contextBindingHash)).thenReturn(restriction);
            assertThat(listener.shouldPublishAuthorizationEvent(event)).as(restriction.name()).isFalse();
            assertThat(listener.shouldPublishSynchronousAuthorizationEvent(event)).as(restriction.name()).isFalse();
        }

        when(actionRepository.getCurrentAction("user-agent-burst", contextBindingHash))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(listener.shouldPublishAuthorizationEvent(event)).isTrue();
        assertThat(listener.shouldPublishSynchronousAuthorizationEvent(event)).isTrue();
    }

    @Test
    @DisplayName("authorization context binding should reuse the ingress request hash")
    void authorizationContextBindingHash_shouldPreferIngressPayload() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-ingress")
                .sessionId("analysis-session")
                .clientIp("198.51.100.9")
                .userAgent("simulated-agent")
                .payload(Map.of("contextBindingHash", "ingress-context-hash"))
                .build();

        assertThat(listener.generateAuthorizationContextBindingHash(event))
                .isEqualTo("ingress-context-hash");
    }

    @Test
    @DisplayName("Disabled zero trust should ignore events")
    void disabled_shouldIgnoreEvents() {
        // given
        when(securityZeroTrustProperties.allowsLlmAnalysis()).thenReturn(false);

        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType("SUCCESS")
                .userId("user-5")
                .build();

        // when
        listener.handleZeroTrustEvent(event);

        // then
        verify(securityEventPublisher, never()).publishGenericSecurityEvent(any());
    }

    @Test
    @DisplayName("Zero trust switched off sends nothing, whatever the mode says")
    void switchedOff_shouldIgnoreEventsWhateverTheMode() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setEnabled(false);
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);

        new ZeroTrustEventListener(securityEventPublisher, actionRepository, properties)
                .handleZeroTrustEvent(ZeroTrustSpringEvent.builder("test")
                        .category(ZeroTrustEventCategory.AUTHENTICATION)
                        .eventType("SUCCESS")
                        .userId("user-5")
                        .build());

        verify(securityEventPublisher, never()).publishGenericSecurityEvent(any());
    }

    /** PR-21: a mode that allows no analysis stopped the method interceptor only; a sign-in still reached the model. */
    @ParameterizedTest
    @EnumSource(value = SecurityZeroTrustProperties.EnforcementMode.class, names = {"DISABLED", "OBSERVE"})
    void aModeWithoutAnalysisSendsNothingToTheAnalysis(SecurityZeroTrustProperties.EnforcementMode mode) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        ZeroTrustEventListener withoutAnalysis = new ZeroTrustEventListener(securityEventPublisher, actionRepository, properties);

        for (ZeroTrustEventCategory category : ZeroTrustEventCategory.values()) {
            withoutAnalysis.handleZeroTrustEvent(ZeroTrustSpringEvent.builder("test")
                    .category(category)
                    .eventType("SUCCESS")
                    .userId("user-6")
                    .sessionId("session-6")
                    .clientIp("10.0.0.6")
                    .build());
        }

        verify(securityEventPublisher, never()).publishGenericSecurityEvent(any());
    }

    @ParameterizedTest
    @EnumSource(value = SecurityZeroTrustProperties.EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void aModeWithAnalysisSendsASecondFactorButNotASignInToIt(SecurityZeroTrustProperties.EnforcementMode mode) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        ZeroTrustEventListener withAnalysis = new ZeroTrustEventListener(securityEventPublisher, actionRepository, properties);

        withAnalysis.handleZeroTrustEvent(ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS)
                .userId("user-7")
                .build());
        verify(securityEventPublisher, never()).publishGenericSecurityEvent(any());

        withAnalysis.handleZeroTrustEvent(ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_MFA)
                .userId("user-7")
                .build());
        verify(securityEventPublisher).publishGenericSecurityEvent(any());
    }

    @Test
    @DisplayName("PENDING_ANALYSIS context whose decision awaits its audit record should not be analyzed again")
    void shouldPublishAuthorizationEvent_decisionAuditPending_shouldSkip() {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-audit-pending")
                .sessionId("session-audit-pending")
                .clientIp("10.0.0.6")
                .userAgent("TestAgent")
                .build();
        String contextBindingHash = listener.generateAuthorizationContextBindingHash(event);
        when(actionRepository.getCurrentAction("user-audit-pending", contextBindingHash))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(actionRepository.isDecisionAuditPending("user-audit-pending", contextBindingHash))
                .thenReturn(true);

        assertThat(listener.shouldPublishAuthorizationEvent(event)).isFalse();

        listener.handleZeroTrustEvent(event);

        verify(securityEventPublisher, never()).publishGenericSecurityEvent(event);
    }

    @Test
    @DisplayName("a request answered by the decision in force is kept in its session without analysis (N-SES-1)")
    void authorizationEvent_decisionInForce_isRecordedWithoutAnalysis() {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        listener.setUnanalysedRequestRecorder(unanalysed);
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-allowed")
                .sessionId("session-allowed")
                .clientIp("10.0.0.7")
                .userAgent("TestAgent")
                .build();
        String contextBindingHash = listener.generateAuthorizationContextBindingHash(event);
        when(actionRepository.getCurrentAction("user-allowed", contextBindingHash)).thenReturn(ZeroTrustAction.ALLOW);

        listener.handleZeroTrustEvent(event);

        verify(securityEventPublisher, never()).publishGenericSecurityEvent(event);
        verify(unanalysed).record(event, ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("a request that goes to analysis is not recorded by the listener (N-SES-1)")
    void authorizationEvent_pendingAnalysis_isNotRecordedByTheListener() {
        UnanalysedRequestRecorder unanalysed = mock(UnanalysedRequestRecorder.class);
        listener.setUnanalysedRequestRecorder(unanalysed);
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-pending")
                .sessionId("session-pending")
                .clientIp("10.0.0.8")
                .userAgent("TestAgent")
                .build();
        when(actionRepository.getCurrentAction(anyString(), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        listener.handleZeroTrustEvent(event);

        verify(securityEventPublisher).publishGenericSecurityEvent(event);
        verify(unanalysed, never()).record(any(), any());
    }
}
