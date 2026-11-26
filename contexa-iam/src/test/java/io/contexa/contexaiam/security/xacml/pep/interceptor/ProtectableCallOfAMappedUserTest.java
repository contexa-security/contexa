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
package io.contexa.contexaiam.security.xacml.pep.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableLlmSuppressionWriter;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.aop.Pointcut;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * bridge v2 (B4): a {@code @Protectable} call of a user the application signed in with a principal object of its own and
 * named with its {@code ContexaSubjectMapper}. The method policies are asked with the application's authentication as
 * it is; the keys the interceptor's own collaborators keep for the user (the rapid re-entry of the actor's session and
 * the record of an analysis skipped for it) carry the user the mapper named, never the text of the object.
 */
@DisplayName("@Protectable 호출은 매퍼가 이름 지은 사용자로 재진입 열쇠와 분석 생략 기록을 남긴다(bridge v2)")
class ProtectableCallOfAMappedUserTest {

    private final ProtectableMethodAuthorizationManager authorizationManager = mock(ProtectableMethodAuthorizationManager.class);
    private final ProtectableRapidReentryRepository reentries = mock(ProtectableRapidReentryRepository.class);
    private final JdbcOperations jdbc = mock(JdbcOperations.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/orders/export");
    private final LegacyMember member = new LegacyMember("kim01", "secret-hash");
    private final Authentication application = UsernamePasswordAuthenticationToken.authenticated(member, null,
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private AuthorizationManagerMethodInterceptor interceptor;

    @BeforeEach
    void setUp() throws Throwable {
        interceptor = new AuthorizationManagerMethodInterceptor(mock(Pointcut.class), authorizationManager,
                new ProtectableRapidReentryGuard(reentries));
        interceptor.setProtectableLlmSuppressionWriter(new ProtectableLlmSuppressionWriter(() -> jdbc,
                new ObjectMapper(), null));
        when(invocation.getMethod()).thenReturn(Orders.class.getMethod("export"));
        when(invocation.getThis()).thenReturn(new Orders());
        when(invocation.proceed()).thenReturn("exported");
        SecurityContextHolder.getContext().setAuthentication(application);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        mapped();
    }

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("매퍼가 이름 지은 사용자의 호출은 그 ID로 빠른 재진입 열쇠를 잡고, 메서드 정책에는 앱의 인증을 그대로 준다")
    void theRapidReentryIsKeyedByTheMappedUser() throws Throwable {
        when(reentries.tryAcquire(anyString(), anyString(), anyString(), any())).thenReturn(true);

        assertThat(interceptor.invoke(invocation)).isEqualTo("exported");

        verify(reentries).tryAcquire(eq("kim01"), anyString(), anyString(), any(Duration.class));
        verify(reentries, never()).tryAcquire(eq(member.toString()), anyString(), anyString(), any());
        assertThat(policyAuthentication()).isSameAs(application);
    }

    @Test
    @DisplayName("빠른 재진입으로 분석을 건너뛴 호출의 기록도 매퍼가 이름 지은 ID로 남고 앱 객체의 값은 남지 않는다")
    void theSkippedAnalysisIsRecordedForTheMappedUser() throws Throwable {
        when(reentries.tryAcquire(anyString(), anyString(), anyString(), any())).thenReturn(false);

        assertThat(interceptor.invoke(invocation)).isEqualTo("exported");

        ArgumentCaptor<Object[]> arguments = ArgumentCaptor.forClass(Object[].class);
        verify(jdbc).update(anyString(), arguments.capture());
        List<Object> written = Arrays.asList(arguments.getValue());
        assertThat(written).contains("kim01").doesNotContain(member.toString());
        assertThat(written).noneSatisfy(value -> assertThat(String.valueOf(value)).contains("secret-hash"));
    }

    /** The identity the bridge filter makes for the request, with the application's mapper. */
    private void mapped() {
        ContexaSubjectMapper mapper = authentication -> authentication.getPrincipal() instanceof LegacyMember legacy
                ? Optional.of(ContexaSubject.of(legacy.empNo(), legacy.empNo() + "@seum.example").build())
                : Optional.empty();
        ContexaIdentity identity = new IdentityResolution(IdentityResolution.Settings.defaults(), null, mapper, null,
                IdentityResolution.Accounts.NONE, new IdentityDiagnostics()).resolve(request, application);
        assertThat(identity.getUserId()).isEqualTo("kim01");
        assertThat(ContexaIdentity.subjectId(application)).as("Contexa reads no field of the application's object")
                .isNull();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
    }

    @SuppressWarnings("unchecked")
    private Authentication policyAuthentication() {
        ArgumentCaptor<Supplier<Authentication>> supplier = ArgumentCaptor.forClass(Supplier.class);
        verify(authorizationManager).protectable(supplier.capture(), eq(invocation));
        return supplier.getValue().get();
    }

    /** An application's own principal object, none of the kinds Spring Security names a user by. */
    record LegacyMember(String empNo, String passwordHash) {
    }

    public static class Orders {
        @Protectable
        public String export() {
            return "exported";
        }
    }
}
