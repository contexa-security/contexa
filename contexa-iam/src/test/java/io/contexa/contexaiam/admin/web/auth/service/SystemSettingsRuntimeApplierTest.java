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
package io.contexa.contexaiam.admin.web.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.SystemSettingsRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ExpressionAuthorizationManagerResolver;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Restart scenario: values stored in {@code system_settings} replace the {@code contexa.policy.*}
 * startup defaults on both the URL and the method enforcement points.
 */
@DisplayName("SystemSettingsRuntimeApplier")
class SystemSettingsRuntimeApplierTest {

    private final SystemSettingsRepository repository = mock(SystemSettingsRepository.class);
    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    private final Authentication user = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));

    private PolicyCombiningProperties properties;
    private CustomDynamicAuthorizationManager urlManager;
    private ProtectableMethodAuthorizationManager methodManager;
    private SecurityZeroTrustProperties zeroTrustProperties;
    private SystemSettingsRuntimeApplier applier;

    @BeforeEach
    void setUp() {
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of());
        when(policyRetrievalPoint.findMethodPolicies(anyString())).thenReturn(List.of());
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("URL", "/api/reports"), "GET",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), inv.getArgument(1)),
                        new HashMap<>()));
        when(contextHandler.create(any(Authentication.class), any(MethodInvocation.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("METHOD", "export"), "INVOKE",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), null), new HashMap<>()));

        // Startup defaults from contexa.policy.* properties
        properties = new PolicyCombiningProperties();
        urlManager = new CustomDynamicAuthorizationManager(policyRetrievalPoint,
                mock(ExpressionAuthorizationManagerResolver.class), mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        urlManager.setCombiningAlgorithm(properties.getCombiningAlgorithm());
        urlManager.setNoMatchingUrlPolicyDecision(properties.getNoMatchingUrlPolicyDecision());
        urlManager.reload();

        CustomMethodSecurityExpressionHandler handler = new CustomMethodSecurityExpressionHandler(
                new SecurityZeroTrustProperties(), mock(CompositePermissionEvaluator.class), new NullRoleHierarchy(),
                policyRetrievalPoint, contextHandler, mock(AuditLogRepository.class),
                mock(ZeroTrustActionRepository.class), properties);
        methodManager = new ProtectableMethodAuthorizationManager(handler, new PolicyCombiningEvaluator());

        zeroTrustProperties = new SecurityZeroTrustProperties();
        applier = new SystemSettingsRuntimeApplier(new SystemRuntimeSettingsService(repository),
                provider(zeroTrustProperties), provider(properties), provider(urlManager));
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }

    private boolean urlGranted() {
        return urlManager.check(() -> user,
                new RequestAuthorizationContext(new MockHttpServletRequest("GET", "/api/reports"))).isGranted();
    }

    private void invokeMethod() throws NoSuchMethodException {
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(ReportService.class.getMethod("export"));
        when(invocation.getThis()).thenReturn(new ReportService());
        when(invocation.getArguments()).thenReturn(new Object[0]);
        methodManager.protectable(() -> user, invocation);
    }

    @Test
    @DisplayName("Stored DENY decisions are applied before requests are served after a restart")
    void storedDecisionsAreAppliedOnStartup() throws Exception {
        assertThat(urlGranted()).isTrue();
        assertThatCode(this::invokeMethod).doesNotThrowAnyException();

        when(repository.findAll()).thenReturn(List.of(SystemSettings.builder()
                .policyCombiningAlgorithm("DENY_UNLESS_PERMIT")
                .noMatchingUrlPolicyDecision("DENY")
                .missingMethodPolicyDecision("DENY")
                .build()));

        applier.afterSingletonsInstantiated();

        assertThat(properties.getCombiningAlgorithm()).isEqualTo(CombiningAlgorithm.DENY_UNLESS_PERMIT);
        assertThat(properties.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
        assertThat(properties.getMissingMethodPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
        assertThat(urlManager.getCombiningAlgorithm()).isEqualTo(CombiningAlgorithm.DENY_UNLESS_PERMIT);
        assertThat(urlManager.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
        assertThat(urlGranted()).isFalse();
        assertThatThrownBy(this::invokeMethod).isInstanceOf(AuthorizationDeniedException.class);
    }

    @Test
    @DisplayName("Application ready re-applies stored policy decisions and zero trust mode")
    void applicationReadyAppliesAllSettings() {
        when(repository.findAll()).thenReturn(List.of(SystemSettings.builder()
                .securityZeroTrustMode("ENFORCE")
                .noMatchingUrlPolicyDecision("DENY")
                .missingMethodPolicyDecision("PERMIT")
                .build()));

        applier.onApplicationEvent(mock(ApplicationReadyEvent.class));

        assertThat(zeroTrustProperties.getMode()).isEqualTo(SecurityZeroTrustProperties.SecurityMode.ENFORCE);
        assertThat(urlManager.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
        assertThat(properties.getMissingMethodPolicyDecision()).isEqualTo(NoPolicyDecision.PERMIT);
    }

    @Test
    @DisplayName("Configured properties stay in effect when no settings row exists")
    void keepsPropertiesWithoutSettingsRow() {
        properties.setCombiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES);
        properties.setNoMatchingUrlPolicyDecision(NoPolicyDecision.DENY);
        when(repository.findAll()).thenReturn(List.of());

        applier.applyPolicyDecisionSettings();

        assertThat(properties.getCombiningAlgorithm()).isEqualTo(CombiningAlgorithm.DENY_OVERRIDES);
        assertThat(properties.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
    }

    @Test
    @DisplayName("Invalid stored values keep the current runtime values")
    void invalidStoredValueKeepsCurrentValues() {
        when(repository.findAll()).thenReturn(List.of(SystemSettings.builder()
                .noMatchingUrlPolicyDecision("SOMETIMES")
                .build()));

        assertThatCode(applier::applyPolicyDecisionSettings).doesNotThrowAnyException();
        assertThat(properties.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.PERMIT);
        assertThat(urlManager.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.PERMIT);
    }

    public static class ReportService {
        public String export() {
            return "report";
        }
    }
}
