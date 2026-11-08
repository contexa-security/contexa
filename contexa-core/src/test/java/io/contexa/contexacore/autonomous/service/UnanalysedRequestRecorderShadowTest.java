package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * A request answered by the decision in force is part of the user's usual behaviour when that decision is an ALLOW, in
 * SHADOW as in ENFORCE: the statistics of a trial in SHADOW are those of ENFORCE. What belongs to a restriction that
 * was enforced (the request sent again after a passed step-up) is left to ENFORCE.
 */
@DisplayName("A request answered by the decision in force counts in SHADOW as in ENFORCE")
class UnanalysedRequestRecorderShadowTest {

    private InMemorySecurityContextDataStore store;
    private ContextObservationRecorder recorder;
    private DefaultSessionNarrativeCollector collector;

    @BeforeEach
    void setUp() {
        store = new InMemorySecurityContextDataStore();
        recorder = new ContextObservationRecorder(store);
        collector = new DefaultSessionNarrativeCollector(store, recorder);
    }

    private static SecurityZeroTrustProperties in(SecurityZeroTrustProperties.EnforcementMode mode) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        return properties;
    }

    private static ZeroTrustSpringEvent event(String requestId) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("requestId", requestId);
        payload.put("httpMethod", "GET");
        payload.put("requestPath", "/api/customers/CUS-0012");
        payload.put("protectableResourceId", "ops.Customers#customer");
        payload.put("granted", true);
        payload.put("className", "ops.Customers");
        payload.put("methodName", "customer");
        return ZeroTrustSpringEvent.builder(UnanalysedRequestRecorderShadowTest.class)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("alice")
                .sessionId("session-1")
                .clientIp("203.0.113.10")
                .userAgent("JUnit")
                .resource("/api/customers/CUS-0012")
                .eventTimestamp(Instant.parse("2026-09-30T03:18:55Z"))
                .payload(payload)
                .build();
    }

    private List<Boolean> learnableWhenAnswered(SecurityZeroTrustProperties.EnforcementMode mode, ZeroTrustAction answer) {
        UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, in(mode), null);
        ZeroTrustSpringEvent event = event("request-" + mode + "-" + answer);
        SecurityEvent request = ZeroTrustSecurityEventConverter.convert(event);
        List<Boolean> learnable = new ArrayList<>();
        recorder.stage(request, ContextObservationRecorder.WORK_PROFILE, null, commit -> learnable.add(commit.learnable()));

        unanalysed.record(event, answer);
        return learnable;
    }

    @Test
    @DisplayName("an ALLOW in force answers a request, which is learnable in ENFORCE and in SHADOW")
    void anAnsweredAllowIsLearnableInEnforceAndInShadow() {
        assertThat(learnableWhenAnswered(SecurityZeroTrustProperties.EnforcementMode.ENFORCE, ZeroTrustAction.ALLOW)).containsExactly(true);
        assertThat(learnableWhenAnswered(SecurityZeroTrustProperties.EnforcementMode.SHADOW, ZeroTrustAction.ALLOW)).containsExactly(true);
    }

    @Test
    @DisplayName("a restriction in force answers a request, which is learnable in neither mode")
    void anAnsweredRestrictionIsLearnableInNeitherMode() {
        assertThat(learnableWhenAnswered(SecurityZeroTrustProperties.EnforcementMode.ENFORCE, ZeroTrustAction.CHALLENGE)).containsExactly(false);
        assertThat(learnableWhenAnswered(SecurityZeroTrustProperties.EnforcementMode.SHADOW, ZeroTrustAction.CHALLENGE)).containsExactly(false);
    }

    @Test
    @DisplayName("where no decision is made (OBSERVE) nothing counts")
    void whereNoDecisionIsMadeNothingCounts() {
        assertThat(learnableWhenAnswered(SecurityZeroTrustProperties.EnforcementMode.OBSERVE, ZeroTrustAction.ALLOW)).containsExactly(false);
    }

    @Test
    @DisplayName("the request sent again after a passed step-up is learned in ENFORCE only, as no step-up is asked in SHADOW")
    void theResentRequestIsLearnedInEnforceOnly() {
        VerificationLearningService verification = mock(VerificationLearningService.class);
        for (SecurityZeroTrustProperties.EnforcementMode mode : List.of(SecurityZeroTrustProperties.EnforcementMode.SHADOW,
                SecurityZeroTrustProperties.EnforcementMode.ENFORCE)) {
            UnanalysedRequestRecorder unanalysed = new UnanalysedRequestRecorder(collector, recorder, in(mode), null);
            unanalysed.setVerificationLearningService(verification);
            unanalysed.record(event("request-resent-" + mode), ZeroTrustAction.ALLOW);
            if (mode == SecurityZeroTrustProperties.EnforcementMode.SHADOW) {
                verify(verification, never()).learnResent(any());
            }
        }
        verify(verification).learnResent(any());
    }
}
