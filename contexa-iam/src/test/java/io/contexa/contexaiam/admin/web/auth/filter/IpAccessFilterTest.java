package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IpAccessFilterTest {

    private final IpAccessRuleService ipAccessRuleService = mock(IpAccessRuleService.class);

    @Test
    void deniesWhenDenyRuleMatches() throws Exception {
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService);
        MockHttpServletRequest request = requestFrom("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("203.0.113.10")).thenReturn(true);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
        verify(ipAccessRuleService, never()).hasActiveAllowRules();
        verify(ipAccessRuleService, never()).isIpAllowed("203.0.113.10");
    }

    @Test
    void allowsWhenNoDenyRuleAndNoActiveAllowRules() throws Exception {
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService);
        MockHttpServletRequest request = requestFrom("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("203.0.113.10")).thenReturn(false);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(false);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        verify(ipAccessRuleService, never()).isIpAllowed("203.0.113.10");
    }

    @Test
    void deniesWhenAllowListIsActiveAndClientDoesNotMatchAllowRule() throws Exception {
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService);
        MockHttpServletRequest request = requestFrom("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("203.0.113.10")).thenReturn(false);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(true);
        when(ipAccessRuleService.isIpAllowed("203.0.113.10")).thenReturn(false);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void allowsWhenAllowListIsActiveAndClientMatchesAllowRule() throws Exception {
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService);
        MockHttpServletRequest request = requestFrom("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("203.0.113.10")).thenReturn(false);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(true);
        when(ipAccessRuleService.isIpAllowed("203.0.113.10")).thenReturn(true);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void denyRuleWinsWhenDenyAndAllowBothMatch() throws Exception {
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService);
        MockHttpServletRequest request = requestFrom("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("203.0.113.10")).thenReturn(true);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(true);
        when(ipAccessRuleService.isIpAllowed("203.0.113.10")).thenReturn(true);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
        verify(ipAccessRuleService, never()).hasActiveAllowRules();
        verify(ipAccessRuleService, never()).isIpAllowed("203.0.113.10");
    }

    @Test
    void ignoresForwardedHeaderWhenTrustedProxyListIsEmpty() throws Exception {
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService);
        MockHttpServletRequest request = requestFrom("10.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("10.0.0.1")).thenReturn(false);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(false);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        verify(ipAccessRuleService).isIpDenied("10.0.0.1");
        verify(ipAccessRuleService, never()).isIpDenied("203.0.113.10");
    }

    @Test
    void usesForwardedHeaderOnlyWhenRemoteAddressIsTrustedProxy() throws Exception {
        TieredStrategyProperties.Security security = new TieredStrategyProperties.Security();
        security.setTrustedProxies(List.of("10.0.0.1"));
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService, security);
        MockHttpServletRequest request = requestFrom("10.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("203.0.113.10")).thenReturn(false);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(false);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        verify(ipAccessRuleService).isIpDenied("203.0.113.10");
        verify(ipAccessRuleService, never()).isIpDenied("10.0.0.1");
    }

    @Test
    void ignoresForwardedHeaderWhenRemoteAddressIsNotTrustedProxy() throws Exception {
        TieredStrategyProperties.Security security = new TieredStrategyProperties.Security();
        security.setTrustedProxies(List.of("10.0.0.1"));
        IpAccessFilter filter = new IpAccessFilter(ipAccessRuleService, security);
        MockHttpServletRequest request = requestFrom("198.51.100.20");
        request.addHeader("X-Forwarded-For", "203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(ipAccessRuleService.isIpDenied("198.51.100.20")).thenReturn(false);
        when(ipAccessRuleService.hasActiveAllowRules()).thenReturn(false);

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        verify(ipAccessRuleService).isIpDenied("198.51.100.20");
        verify(ipAccessRuleService, never()).isIpDenied("203.0.113.10");
    }

    private MockHttpServletRequest requestFrom(String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/users");
        request.setRemoteAddr(remoteAddr);
        return request;
    }
}
