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
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.NewContextDecisionLimit;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * A person who signs in again and again buys a model decision with each sign-in. Past the decisions of a new context
 * allowed in the window, a sign-in goes on undecided: it is kept in its session and the person's next request is asked
 * to verify. The sign-in itself is never refused.
 */
class SignInDecisionLimitTest {

    private static final String USER = "alice";

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    private final SecurityEventPublisher engine = mock(SecurityEventPublisher.class);
    private final UnanalysedRequestRecorder recorder = mock(UnanalysedRequestRecorder.class);
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    private NewContextDecisionLimit limit;
    private ZeroTrustEventListener listener;

    @BeforeEach
    void setUp() {
        limit = new NewContextDecisionLimit(properties.getAnalysis().getNewContextLimit(), null, clock);
        listener = new ZeroTrustEventListener(engine, repository, properties);
        listener.setUnanalysedRequestRecorder(recorder);
        listener.setNewContextDecisionLimit(limit);
    }

    private static ZeroTrustSpringEvent signIn(String user, String nextContext, Map<String, Object> facts) {
        Map<String, Object> payload = new HashMap<>(facts);
        payload.put("contextBindingHash", nextContext);
        payload.put("authenticationType", "MFA");
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId(user).sessionId("session-" + nextContext)
                .clientIp("10.0.0.1").userAgent("browser").payload(payload).build();
    }

    private static ZeroTrustSpringEvent signIn(String nextContext) {
        return signIn(USER, nextContext, Map.of());
    }

    private void signsIn(int times) {
        for (int i = 0; i < times; i++) {
            listener.handleZeroTrustEvent(signIn("context-" + i));
        }
    }

    @Test
    @DisplayName("six sign-ins are decided; the seventh goes on undecided, kept in its session, and its session is asked to verify")
    void theSeventhSignInGoesOnUndecided() {
        signsIn(6);
        verify(engine, times(6)).publishGenericSecurityEvent(any());

        ZeroTrustSpringEvent seventh = signIn("context-6");
        listener.handleZeroTrustEvent(seventh);

        verify(engine, times(6)).publishGenericSecurityEvent(any());
        verify(engine, never()).publishGenericSecurityEvent(seventh);
        verify(recorder).record(seventh, ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(USER, "context-6")).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.decidedContext(USER)).isEqualTo("context-6");
        assertThat(repository.isTechnicalChallenge(USER)).isFalse();
        assertThat(repository.getAnalysisData(USER).reasoning()).contains("sign-in");
    }

    @Test
    @DisplayName("every session of the person is asked, as a decided CHALLENGE asks it")
    void everySessionIsAsked() {
        repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, Map.of("observationId", "observation-1",
                "processingGeneration", "1", "contextBindingHash", "context-home"));

        signsIn(7);

        assertThat(repository.getCurrentAction(USER, "context-home")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "ESCALATE"})
    @DisplayName("a stricter decision in force stays as it was")
    void aStricterDecisionStays(ZeroTrustAction stricter) {
        repository.writeFinalAction(USER, stricter, Map.of("observationId", "observation-1",
                "processingGeneration", "1", "contextBindingHash", "context-home"));

        signsIn(7);

        assertThat(repository.getCurrentAction(USER, "context-6")).isEqualTo(stricter);
    }

    @Test
    @DisplayName("another person's sign-ins count apart, and a console session's apart from the user of that name")
    void eachPersonCountsApart() {
        signsIn(7);

        listener.handleZeroTrustEvent(signIn("bob", "context-bob", Map.of()));
        ZeroTrustSpringEvent console = signIn(USER, "context-console", Map.of("executionSubjectKind", "CONSOLE_ADMIN"));
        listener.handleZeroTrustEvent(console);

        verify(engine, times(8)).publishGenericSecurityEvent(any());
        verify(engine).publishGenericSecurityEvent(console);
        assertThat(repository.getCurrentAction("bob", "context-bob")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("the person's changed contexts and sign-ins share the window")
    void changedContextsAndSignInsShareTheWindow() {
        for (int i = 0; i < 6; i++) {
            limit.take(USER, NewContextDecisionLimit.Kind.CHANGED_CONTEXT);
        }

        listener.handleZeroTrustEvent(signIn("context-0"));

        verify(engine, never()).publishGenericSecurityEvent(any());
        assertThat(repository.getCurrentAction(USER, "context-0")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("past the window the sign-ins are decided again")
    void pastTheWindowTheyAreDecidedAgain() {
        signsIn(7);
        clock.advance(Duration.ofSeconds(61));

        listener.handleZeroTrustEvent(signIn("context-later"));

        verify(engine, times(7)).publishGenericSecurityEvent(any());
    }

    @Test
    @DisplayName("where decisions are not enforced, a sign-in past the limit is not analysed and nothing is stored")
    void notEnforcedNothingIsStored() {
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);

        signsIn(7);

        verify(engine, times(6)).publishGenericSecurityEvent(any());
        assertThat(repository.getCurrentAction(USER, "context-6")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("a sign-in inside a shadow boundary past the limit is not analysed and nothing is stored")
    void aShadowBoundaryStoresNothing() {
        for (int i = 0; i < 7; i++) {
            listener.handleZeroTrustEvent(signIn(USER, "context-" + i, Map.of("decisionBoundaryMode", "SHADOW")));
        }

        verify(engine, times(6)).publishGenericSecurityEvent(any());
        assertThat(repository.getCurrentAction(USER, "context-6")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("the CHALLENGE goes to the store with what was known of the sign-in, and the store's answer is final")
    void theChallengeIsWrittenOnce() {
        ZeroTrustActionRepository store = mock(ZeroTrustActionRepository.class);
        listener = new ZeroTrustEventListener(engine, store, properties);
        listener.setNewContextDecisionLimit(limit);
        for (int i = 0; i < 6; i++) {
            limit.take(USER, NewContextDecisionLimit.Kind.SIGN_IN);
        }

        listener.handleZeroTrustEvent(signIn("context-6"));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(store).writeUndecidedChallenge(eq(USER), fields.capture());
        assertThat(fields.getValue()).containsEntry("contextBindingHash", "context-6")
                .containsEntry(ZeroTrustActionRepository.LLM_DECISION_PRESENT, false)
                .doesNotContainKey(ZeroTrustActionRepository.TECHNICAL_CHALLENGE);
        verify(store, never()).saveAction(any(), any(), any());
    }

    @Test
    @DisplayName("an authorization event is not a sign-in and is not counted here")
    void anAuthorizationIsNoSignIn() {
        signsIn(6);
        ZeroTrustSpringEvent call = ZeroTrustSpringEvent.builder(new Object())
                .category(ZeroTrustEventCategory.AUTHORIZATION).eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId(USER).sessionId("session-x").clientIp("10.0.0.1").userAgent("browser")
                .payload(new HashMap<>(Map.of("contextBindingHash", "context-x"))).build();

        listener.handleZeroTrustEvent(call);

        verify(engine).publishGenericSecurityEvent(call);
        assertThat(List.of(repository.getCurrentAction(USER, "context-x"))).containsExactly(ZeroTrustAction.PENDING_ANALYSIS);
    }
}
