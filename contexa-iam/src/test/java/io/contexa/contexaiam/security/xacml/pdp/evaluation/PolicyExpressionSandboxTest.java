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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.CustomWebSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Evaluation-time hardening of the URL policy expression handler.
 */
class PolicyExpressionSandboxTest {

    private final SpelExpressionParser parser = new SpelExpressionParser();
    private EvaluationContext context;

    @BeforeEach
    void setUp() {
        ContextHandler contextHandler = mock(ContextHandler.class);
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("URL", "/api/orders"), "GET",
                        new EnvironmentDetails("192.168.1.10", LocalDateTime.now(), inv.getArgument(1)),
                        new HashMap<>()));
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler(
                contextHandler, mock(AuditLogRepository.class), mock(ZeroTrustActionRepository.class),
                new NullRoleHierarchy());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders");
        request.setRemoteAddr("192.168.1.10");
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
        context = handler.createEvaluationContext(() -> authentication, new RequestAuthorizationContext(request));
    }

    private Object evaluate(String expression) {
        return parser.parseExpression(expression).getValue(context);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "T(java.lang.Runtime).getRuntime()",
            "T(java.lang.System).getenv()",
            "new java.lang.ProcessBuilder('calc')",
            "new java.io.File('/tmp')",
            "''.getClass().forName('java.lang.Runtime')",
            "''.class.forName('java.lang.Runtime')",
            "''.class",
            "T(java.time.LocalTime).forName('java.lang.Runtime')",
            "T(java.time.LocalTime).classLoader",
            "T(java.time.LocalTime).getName()",
            "T(int).getName()",
            "@systemSettingsService",
            "authentication.authenticated = false",
            "#ai.authentication.getClass()"
    })
    @DisplayName("Type references, constructors, reflection, bean references and writes are rejected")
    void dangerousExpressionsFailAtEvaluation(String expression) {
        assertThatThrownBy(() -> evaluate(expression)).isInstanceOf(EvaluationException.class);
    }

    @Test
    @DisplayName("Spring Security root functions and AI variable keep working")
    void securityFunctionsStillWork() {
        assertThat(evaluate("hasRole('ADMIN')")).isEqualTo(true);
        assertThat(evaluate("hasAuthority('ROLE_ADMIN')")).isEqualTo(true);
        assertThat(evaluate("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")).isEqualTo(true);
        assertThat(evaluate("isAuthenticated()")).isEqualTo(true);
        assertThat(evaluate("isFullyAuthenticated()")).isEqualTo(true);
        assertThat(evaluate("isAnonymous()")).isEqualTo(false);
        assertThat(evaluate("hasIpAddress('192.168.1.0/24')")).isEqualTo(true);
        assertThat(evaluate("permitAll")).isEqualTo(true);
        assertThat(evaluate("denyAll")).isEqualTo(false);
        assertThat(evaluate("principal == 'alice'")).isEqualTo(true);
        assertThat(evaluate("authentication.name")).isEqualTo("alice");
        assertThat(evaluate("#ai.hasRole('ADMIN')")).isEqualTo(true);
        assertThat(evaluate("httpMethod")).isEqualTo("GET");
    }

    @Test
    @DisplayName("Allowed java.time value types can be used for business-hour conditions")
    void javaTimeValueTypesAreAllowed() {
        assertThat(evaluate("T(java.time.LocalTime).now().hour >= 0 && T(java.time.LocalTime).now().hour <= 23"))
                .isEqualTo(true);
        assertThat(evaluate("T(java.time.DayOfWeek).MONDAY.value")).isEqualTo(1);
        assertThat(evaluate("T(java.time.LocalDate).now().dayOfWeek != null")).isEqualTo(true);
    }

    @Test
    @DisplayName("Sandbox can be applied to any standard evaluation context")
    void sandboxRestrictsPlainContext() {
        StandardEvaluationContext plainContext = new StandardEvaluationContext("value");
        PolicyExpressionSandbox.apply(plainContext);

        assertThat(parser.parseExpression("length()").getValue(plainContext)).isEqualTo(5);
        assertThatThrownBy(() -> parser.parseExpression("T(java.lang.Runtime)").getValue(plainContext))
                .isInstanceOf(EvaluationException.class);
        assertThatThrownBy(() -> parser.parseExpression("bytes.class").getValue(plainContext))
                .isInstanceOf(EvaluationException.class);
    }
}
