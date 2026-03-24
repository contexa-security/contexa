package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.CompositeAuthBridge;
import io.contexa.contexacommon.security.bridge.RequestAttributeAuthBridge;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationDetails;
import io.contexa.contexacommon.security.bridge.authentication.BridgeAuthenticationToken;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.resolver.AuthBridgeAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.RequestAttributeAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.RequestAttributeDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RequestAttributeBridgeResolutionFilterTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldResolveBridgeContextFromRequestAttributesWithoutContainerPrincipal() throws Exception {
        BridgeProperties properties = new BridgeProperties();
        BridgeResolutionFilter filter = new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new AuthBridgeAuthenticationStampResolver(new CompositeAuthBridge(List.of(
                        new RequestAttributeAuthBridge(properties.getAuthentication().getRequestAttributes())
                )))),
                List.of(new RequestAttributeAuthorizationStampResolver()),
                List.of(new RequestAttributeDelegationStampResolver()),
                new BridgeCoverageEvaluator()
        );

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/finance/reports/quarterly/approve");
        request.setAttribute("ctxa.auth.principalId", "carol");
        request.setAttribute("ctxa.auth.displayName", "Carol Reviewer");
        request.setAttribute("ctxa.auth.authenticated", true);
        request.setAttribute("ctxa.auth.authorities", "ROLE_MANAGER,REPORT_APPROVE");
        request.setAttribute("ctxa.auth.type", "BIOMETRIC");
        request.setAttribute("ctxa.auth.assurance", "HIGH");
        request.setAttribute("ctxa.auth.mfaCompleted", true);
        request.setAttribute("ctxa.auth.time", "2026-03-23T09:00:00Z");
        request.setAttribute("ctxa.authz.effect", "ALLOW");
        request.setAttribute("ctxa.authz.privileged", true);
        request.setAttribute("ctxa.authz.policyId", "policy-approve");
        request.setAttribute("ctxa.authz.policyVersion", "2026.03");
        request.setAttribute("ctxa.authz.scopeTags", "finance,approval");
        request.setAttribute("ctxa.authz.roles", "ROLE_MANAGER");
        request.setAttribute("ctxa.authz.authorities", "REPORT_APPROVE");
        request.setAttribute("ctxa.delegation.enabled", true);
        request.setAttribute("ctxa.delegation.agentId", "agent-99");
        request.setAttribute("ctxa.delegation.objectiveId", "objective-99");
        request.setAttribute("ctxa.delegation.objectiveSummary", "Approve quarterly report");
        request.setAttribute("ctxa.delegation.allowedOperations", "APPROVE,READ");
        request.setAttribute("ctxa.delegation.allowedResources", "report:quarterly");
        request.setAttribute("ctxa.delegation.approvalRequired", true);
        request.setAttribute("ctxa.delegation.containmentOnly", false);
        request.setAttribute("ctxa.delegation.expiresAt", "2026-03-24T00:00:00Z");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp()).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("carol");
        assertThat(result.authenticationStamp().authenticationSource()).isEqualTo("REQUEST_ATTRIBUTE");
        assertThat(result.authorizationStamp()).isNotNull();
        assertThat(result.authorizationStamp().subjectId()).isEqualTo("carol");
        assertThat(result.authorizationStamp().policyVersion()).isEqualTo("2026.03");
        assertThat(result.authorizationStamp().effectiveAuthorities()).contains("REPORT_APPROVE");
        assertThat(result.delegationStamp()).isNotNull();
        assertThat(result.delegationStamp().subjectId()).isEqualTo("carol");
        assertThat(result.delegationStamp().expiresAt()).isEqualTo(Instant.parse("2026-03-24T00:00:00Z"));
        assertThat(result.coverageReport().level()).isEqualTo(BridgeCoverageLevel.DELEGATION_CONTEXT);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isInstanceOf(BridgeAuthenticationToken.class);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("carol");
        BridgeAuthenticationDetails details = (BridgeAuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
        assertThat(details.bridgeAuthenticationSource()).isEqualTo("REQUEST_ATTRIBUTE");
        assertThat(details.bridgeAuthorizationSource()).isEqualTo("REQUEST_ATTRIBUTE");
        assertThat(details.bridgeDelegationSource()).isEqualTo("REQUEST_ATTRIBUTE");
        assertThat(details.policyVersion()).isEqualTo("2026.03");
    }
}

