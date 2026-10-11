package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A real authorization denial is kept as a session record line and a denied scope observation, without analysis
 * (W1-6).
 */
class AuthorizationDenialRecorderTest {

    @Test
    void aDenialBecomesASessionLineAndADeniedScopeObservation() throws Exception {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        RoleScopeCollector roleScopeCollector = mock(RoleScopeCollector.class);
        MethodInvocation invocation = mock(MethodInvocation.class);
        Method method = Object.class.getMethod("toString");
        when(invocation.getMethod()).thenReturn(method);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken("eng-k", "n/a", List.of());
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("eng-k")
                .sessionId("session-7")
                .clientIp("10.40.12.20")
                .resource("/api/customers/CUS-0001")
                .payload(Map.of("granted", false, "httpMethod", "GET", "requestPath", "/api/customers/CUS-0001"))
                .build();
        when(publisher.buildMethodAuthorizationEvent(eq(invocation), eq(authentication), eq(false),
                eq("role cannot read customers"), eq(ZeroTrustEventPublisher.METHOD_NOT_RUN), any()))
                .thenReturn(event);

        new AuthorizationDenialRecorder(publisher, dataStore, roleScopeCollector)
                .record(invocation, authentication, "role cannot read customers");

        ArgumentCaptor<String> line = ArgumentCaptor.forClass(String.class);
        verify(dataStore).addSessionAction(eq("session-7"), line.capture());
        assertThat(line.getValue()).contains("AUTHORIZATION_DENIED", "GET /api/customers/CUS-0001");
        ArgumentCaptor<SecurityEvent> collected = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(roleScopeCollector).collect(collected.capture());
        assertThat(collected.getValue().getMetadata()).containsEntry("granted", false);
    }

    @Test
    void aDenialIsKeptInTheSessionDecisionHistory() throws Exception {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(Object.class.getMethod("toString"));
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken("eng-k", "n/a", List.of());
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("eng-k")
                .sessionId("session-9")
                .clientIp("10.40.12.20")
                .resource("/api/customers/CUS-0001")
                .payload(Map.of("granted", false, "httpMethod", "GET", "requestPath", "/api/customers/CUS-0001"))
                .build();
        when(publisher.buildMethodAuthorizationEvent(eq(invocation), eq(authentication), eq(false),
                eq("role cannot read customers"), eq(ZeroTrustEventPublisher.METHOD_NOT_RUN), any()))
                .thenReturn(event);

        new AuthorizationDenialRecorder(publisher, dataStore, mock(RoleScopeCollector.class))
                .record(invocation, authentication, "role cannot read customers");

        // A refused authorization is one of the session's decisions, so the next request can count it (W1-11).
        ArgumentCaptor<String> line = ArgumentCaptor.forClass(String.class);
        verify(dataStore).addSessionDecision(eq("session-9"), line.capture());
        SessionDecisionRecord record = SessionDecisionRecord.decode(line.getValue());
        assertThat(record).isNotNull();
        assertThat(record.method()).isEqualTo("GET");
        assertThat(record.path()).isEqualTo("/api/customers/CUS-0001");
        assertThat(record.outcome()).isEqualTo(SessionDecisionRecord.AUTHORIZATION_DENIED);
    }

    @Test
    void aUrlPolicyRefusalIsKeptTheSameWay() {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        RoleScopeCollector roleScopeCollector = mock(RoleScopeCollector.class);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken("eng-k", "n/a", List.of());
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder(this)
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD)
                .userId("eng-k")
                .sessionId("session-8")
                .clientIp("10.40.12.21")
                .resource("/api/customers/CUS-0001")
                .payload(Map.of("granted", false, "authorizationCheck", "URL_POLICY", "httpMethod", "GET",
                        "requestPath", "/api/customers/CUS-0001"))
                .build();
        when(publisher.buildRequestAuthorizationEvent(eq(authentication), eq(false), any())).thenReturn(event);

        new AuthorizationDenialRecorder(publisher, dataStore, roleScopeCollector)
                .recordRequest(authentication, "URL authorization policy denied the request");

        verify(dataStore).addSessionAction(eq("session-8"), any());
        verify(roleScopeCollector).collect(any());
    }
}
