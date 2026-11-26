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
package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthenticatedExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthorityExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.CustomWebSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-7 of docs/agent/운영모드-정상화-구현계획.md: the URL policies on the application's requests, behind the application's
 * chain, with the manager of Contexa's own chain. A request no policy decides stays with the application's decision.
 */
@DisplayName("고객 경로의 URL 정책 집행 필터(R-7)")
class UrlPolicyEnforcementFilterTest {

    private static final String OPEN = "/h/open/info";
    private static final String STAFF = "/h/open/staff/report";
    private static final String UNNAMED = "/h/secured/data";
    /** Every request is the application's: a chain of the application took it, or none did. */
    private static final RequestMatcher THE_APPLICATIONS = request -> true;
    /** Every request is taken by one of Contexa's own chains. */
    private static final RequestMatcher CONTEXAS_OWN = request -> false;

    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final List<String> contexaWorkSeenByTheDecision = new ArrayList<>();
    private ExpressionAuthorizationManagerResolver resolver;

    private final Authentication anonymous = new AnonymousAuthenticationToken(
            "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Authentication user = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final Authentication administrator = UsernamePasswordAuthenticationToken.authenticated(
            "root", "n/a", AuthorityUtils.createAuthorityList("ROLE_ADMIN"));

    @BeforeEach
    void setUp() {
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> {
                    contexaWorkSeenByTheDecision.add("decision " + RequestPathScope.inContexaWork());
                    return new AuthorizationContext(inv.getArgument(0), null,
                            new ResourceDetails("URL", ((HttpServletRequest) inv.getArgument(1)).getRequestURI()), "GET",
                            new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), inv.getArgument(1)),
                            new HashMap<>());
                });
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler(
                contextHandler, mock(AuditLogRepository.class), mock(ZeroTrustActionRepository.class),
                new NullRoleHierarchy());
        resolver = new ExpressionAuthorizationManagerResolver(List.of(
                new AuthenticatedExpressionEvaluator(),
                new AuthorityExpressionEvaluator(),
                new WebSpelExpressionEvaluator()), handler);
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("정책이 없는 경로는 판정을 보류해 고객 결정을 그대로 둔다(정책 없음 기본값은 쓰지 않는다)")
    void aRequestNoPolicyNamesKeepsTheApplicationsDecision() throws Exception {
        CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE);
        signedIn(anonymous);
        MockHttpServletRequest request = apiRequest(UNNAMED);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(request, response, passed);

        assertThat(passed.count).isEqualTo(1);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsByteArray()).isEmpty();
        assertThat(CustomDynamicAuthorizationManager.decided(request)).as("an abstention leaves no decision").isFalse();
        verify(audit, never()).recordAsync(any(AuditRecord.class));
        assertThat(manager.check(() -> anonymous, new RequestAuthorizationContext(apiRequest(UNNAMED))).isGranted())
                .as("Contexa's own chain refuses it by its default; the application's path keeps the application's decision")
                .isFalse();
    }

    @Test
    @DisplayName("경로를 이름 짓지만 적용되지 않는 DENY 정책도 판정을 보류한다")
    void aDenyPolicyThatDoesNotApplyDecidesNothing() throws Exception {
        CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                policy(1L, Policy.Effect.DENY, 10, "/**", "hasAuthority('ROLE_BLOCKED')"));
        signedIn(anonymous);
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(apiRequest(UNNAMED), new MockHttpServletResponse(), passed);

        assertThat(passed.count).isEqualTo(1);
    }

    @Test
    @DisplayName("정책이 허용한 요청은 고객 처리로 간다")
    void aRequestAPolicyGrantsGoesOn() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        signedIn(anonymous);
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(apiRequest(OPEN), new MockHttpServletResponse(), passed);

        assertThat(passed.count).isEqualTo(1);
    }

    @Test
    @DisplayName("앱이 열어 둔 경로라도 정책이 거부하면 막는다: 로그인 안 한 API 요청은 401 JSON")
    void aRefusalOfARequestWithoutAUserIsUnauthorized() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        signedIn(anonymous);
        MockHttpServletRequest request = apiRequest(STAFF);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(request, response, passed);

        assertThat(passed.count).isZero();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/json");
        JsonNode body = new ObjectMapper().readTree(response.getContentAsString());
        assertThat(body.path("error").asText()).isEqualTo(UrlPolicyEnforcementFilter.DENIED);
        assertThat(body.path("path").asText()).isEqualTo(STAFF);
        verify(audit, times(1)).recordAsync(any(AuditRecord.class));
    }

    @Test
    @DisplayName("로그인한 사용자의 요청을 정책이 거부하면 403")
    void aRefusalOfASignedInUserIsForbidden() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        signedIn(user);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(apiRequest(STAFF), response, passed);

        assertThat(passed.count).isZero();
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    @DisplayName("브라우저 요청의 거부는 앱의 오류 처리로 보낸다")
    void aBrowsersRefusalGoesThroughTheApplicationsErrorHandling() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        signedIn(anonymous);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", STAFF);
        request.addHeader("Accept", "text/html");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(request, response, passed);

        assertThat(passed.count).isZero();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsByteArray()).as("the error page is the application's").isEmpty();
        assertThat(response.isCommitted()).isTrue();
    }

    @Test
    @DisplayName("어느 체인도 맡지 않아 사용자가 없는 요청은 익명으로 판정한다")
    void aRequestNoChainTookIsAnonymous() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(apiRequest(STAFF), response, passed);

        assertThat(passed.count).isZero();
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("체인에서 매니저가 이미 판정한 요청은 다시 판정하지 않는다")
    void aRequestTheManagerDecidedOnAChainIsNotDecidedAgain() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        MockHttpServletRequest request = apiRequest(STAFF);
        assertThat(manager.check(() -> administrator, new RequestAuthorizationContext(request)).isGranted()).isTrue();
        signedIn(anonymous);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, THE_APPLICATIONS).doFilter(request, response, passed);

        assertThat(passed.count).as("an anonymous judgment again would refuse it").isEqualTo(1);
        assertThat(response.getStatus()).isEqualTo(200);
        verify(audit, times(1)).recordAsync(any(AuditRecord.class));
    }

    @Test
    @DisplayName("Contexa 자기 체인이 맡은 요청은 그 체인의 몫이라 보지 않는다")
    void aRequestOneOfContexasOwnChainsTookIsThatChains() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        signedIn(anonymous);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed passed = new Passed();

        filter(manager, CONTEXAS_OWN).doFilter(apiRequest(STAFF), response, passed);

        assertThat(passed.count).isEqualTo(1);
        assertThat(response.getStatus()).isEqualTo(200);
        verify(audit, never()).recordAsync(any(AuditRecord.class));
    }

    @Test
    @DisplayName("판정은 Contexa 작업 범위에서 하고 고객 처리는 그 밖에서 돈다")
    void theDecisionIsContexasWorkAndTheApplicationRunsOutsideIt() throws Exception {
        CustomDynamicAuthorizationManager manager = staffPolicies();
        signedIn(anonymous);
        List<String> seen = contexaWorkSeenByTheDecision;
        FilterChain application = (request, response) -> seen.add("application " + RequestPathScope.inContexaWork());

        filter(manager, THE_APPLICATIONS).doFilter(apiRequest(OPEN), new MockHttpServletResponse(), application);

        assertThat(seen).hasSizeGreaterThan(1);
        assertThat(seen.subList(0, seen.size() - 1)).allMatch("decision true"::equals);
        assertThat(seen.get(seen.size() - 1)).isEqualTo("application false");
        assertThat(RequestPathScope.inContexaWork()).isFalse();
    }

    private CustomDynamicAuthorizationManager staffPolicies() {
        return manager(CombiningAlgorithm.FIRST_APPLICABLE,
                policy(1L, Policy.Effect.ALLOW, 10, OPEN, "permitAll"),
                policy(2L, Policy.Effect.ALLOW, 20, "/h/open/staff/**", "hasAuthority('ROLE_ADMIN')"));
    }

    private UrlPolicyEnforcementFilter filter(CustomDynamicAuthorizationManager manager, RequestMatcher applicationRequests) {
        return new UrlPolicyEnforcementFilter(manager, applicationRequests, new ObjectMapper());
    }

    private void signedIn(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private static MockHttpServletRequest apiRequest(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.addHeader("Accept", "application/json");
        return request;
    }

    private Policy policy(long id, Policy.Effect effect, int priority, String path, String... conditions) {
        Policy policy = Policy.builder().id(id).name("policy-" + id).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(path).httpMethod("ANY").build());
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        Set<PolicyCondition> conditionSet = new HashSet<>();
        for (String condition : conditions) {
            conditionSet.add(PolicyCondition.builder().rule(rule).expression(condition).build());
        }
        rule.setConditions(conditionSet);
        policy.getRules().add(rule);
        return policy;
    }

    /** The manager as Contexa's chain gets it, with its default for a URL no policy names (AUTHENTICATED). */
    private CustomDynamicAuthorizationManager manager(CombiningAlgorithm algorithm, Policy... policies) {
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policies));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), audit, new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(algorithm);
        manager.reload();
        return manager;
    }

    @Test
    @DisplayName("정책 평가가 실패하면 판정을 보류하고 고객 요청을 그대로 넘긴다")
    void aFailureToEvaluateThePoliciesLeavesTheRequestToTheApplication() throws Exception {
        CustomDynamicAuthorizationManager failing = mock(CustomDynamicAuthorizationManager.class);
        when(failing.checkNamedPolicies(any(), any())).thenThrow(new IllegalStateException("the policy store is down"));
        UrlPolicyEnforcementFilter filter = new UrlPolicyEnforcementFilter(failing, request -> true, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/h/open/staff/report");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Passed application = new Passed();

        filter.doFilter(request, response, application);

        assertThat(application.count).isEqualTo(1);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.isCommitted()).isFalse();
    }

    /** The application's part of the request: counts how often the request reached it. */
    private static final class Passed implements FilterChain {

        private int count;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response) {
            count++;
        }
    }
}
