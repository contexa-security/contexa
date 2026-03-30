package io.contexa.contexacore.hcad.filter;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoSettings;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HCADFilterTest {

    @Mock
    private HCADAnalysisService hcadAnalysisService;

    @Mock
    private HcadProperties hcadProperties;

    private HCADFilter hcadFilter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        hcadFilter = new HCADFilter(hcadAnalysisService, hcadProperties);
        request = new MockHttpServletRequest();
        request.setRequestURI("/api/test");
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Normal analysis stores context attributes in request")
    void doFilterInternal_normalAnalysis_storesContextInRequest() throws Exception {
        // given
        when(hcadProperties.isEnabled()).thenReturn(true);
        setAuthenticated();

        HCADContext ctx = new HCADContext();
        ctx.setIsNewSession(false);
        ctx.setNewUser(false);
        ctx.setIsNewDevice(false);
        ctx.setRecentRequestCount(5);
        ctx.setFailedLoginAttempts(0);
        ctx.setBaselineConfidence(0.8);
        ctx.setIsSensitiveResource(true);
        ctx.setHasValidMFA(true);
        ctx.setAuthenticationMethod("mfa");
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("userRoles", "[ROLE_USER]");
        attrs.put("resourceSensitivity", "CRITICAL");
        ctx.setAdditionalAttributes(attrs);

        HCADAnalysisResult result = HCADAnalysisResult.builder()
                .userId("testUser")
                .trustScore(0.9)
                .threatType("NONE")
                .threatEvidence("")
                .isAnomaly(false)
                .anomalyScore(0.1)
                .action("ALLOW")
                .confidence(0.95)
                .processingTimeMs(10)
                .context(ctx)
                .build();

        when(hcadAnalysisService.analyze(any(), any())).thenReturn(result);

        // when
        hcadFilter.doFilterInternal(request, response, filterChain);

        // then
        assertThat(request.getAttribute("hcad.is_new_session")).isEqualTo(false);
        assertThat(request.getAttribute("hcad.is_new_user")).isEqualTo(false);
        assertThat(request.getAttribute("hcad.is_new_device")).isEqualTo(false);
        assertThat(request.getAttribute("hcad.recent_request_count")).isEqualTo(5);
        assertThat(request.getAttribute("hcad.failed_login_attempts")).isEqualTo(0);
        assertThat(request.getAttribute("hcad.baseline_confidence")).isEqualTo(0.8);
        assertThat(request.getAttribute("hcad.is_sensitive_resource")).isEqualTo(true);
        assertThat(request.getAttribute("hcad.mfa_verified")).isEqualTo(true);
        assertThat(request.getAttribute("hcad.auth_method")).isEqualTo("mfa");
        assertThat(request.getAttribute("hcad.resource_sensitivity")).isEqualTo("CRITICAL");
        assertThat(request.getAttribute("hcad.user_roles")).isEqualTo("[ROLE_USER]");
    }

    @Test
    @DisplayName("shouldNotFilter returns true for static paths")
    void shouldNotFilter_staticPaths_returnsTrue() {
        request.setRequestURI("/static/css/main.css");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/css/style.css");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/js/app.js");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/images/logo.png");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter returns true for health and actuator paths")
    void shouldNotFilter_healthAndActuator_returnsTrue() {
        request.setRequestURI("/health");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/actuator/health");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/actuator/info");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter returns false for API paths")
    void shouldNotFilter_apiPaths_returnsFalse() {
        request.setRequestURI("/api/users");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("Unauthenticated request passes through without analysis")
    void doFilterInternal_unauthenticated_passesThrough() throws Exception {
        // given
        when(hcadProperties.isEnabled()).thenReturn(true);
        // no authentication set in SecurityContextHolder

        // when
        hcadFilter.doFilterInternal(request, response, filterChain);

        // then - filterChain.doFilter was called (request passed through MockFilterChain)
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Exception during analysis results in graceful passthrough")
    void doFilterInternal_exceptionDuringAnalysis_gracefulPassthrough() throws Exception {
        // given
        when(hcadProperties.isEnabled()).thenReturn(true);
        setAuthenticated();
        when(hcadAnalysisService.analyze(any(), any()))
                .thenThrow(new RuntimeException("Analysis failed"));

        // when
        hcadFilter.doFilterInternal(request, response, filterChain);

        // then - filter chain still called
        assertThat(filterChain.getRequest()).isNotNull();
        assertThat(request.getAttribute("hcad.analysisStatus")).isEqualTo("FAILED");
        assertThat(request.getAttribute("hcad.failReason")).isEqualTo("RuntimeException");
    }

    @Test
    @DisplayName("Disabled HCAD passes through without analysis")
    void doFilterInternal_disabled_passesThrough() throws Exception {
        // given
        when(hcadProperties.isEnabled()).thenReturn(false);
        setAuthenticated();

        // when
        hcadFilter.doFilterInternal(request, response, filterChain);

        // then
        assertThat(filterChain.getRequest()).isNotNull();
    }

    private void setAuthenticated() {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("testUser", "password", Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
