package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HCADContextExtractorTest {

    @Mock
    private HCADDataStore hcadDataStore;

    @Mock
    private SecurityContextDataStore securityContextDataStore;

    @Mock
    private HcadProperties hcadProperties;

    private HCADContextExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new HCADContextExtractor(hcadDataStore, securityContextDataStore, hcadProperties);

        HcadProperties.ResourceSettings resourceSettings = new HcadProperties.ResourceSettings();
        when(hcadProperties.getResource()).thenReturn(resourceSettings);

        when(hcadDataStore.getSessionMetadata(anyString())).thenReturn(Collections.emptyMap());
        when(hcadDataStore.isDeviceRegistered(anyString(), anyString())).thenReturn(false);
        when(hcadDataStore.isUserRegistered(anyString())).thenReturn(true);
        when(hcadDataStore.getRecentRequestCount(anyString(), anyLong(), anyLong())).thenReturn(1);
        when(hcadDataStore.isMfaVerified(anyString())).thenReturn(false);
    }

    @Test
    @DisplayName("Should extract basic context: userId, IP, path, method")
    void shouldExtractBasicContext() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        request.setMethod("GET");
        request.setRemoteAddr("192.168.1.1");
        request.addHeader("User-Agent", "Mozilla/5.0");

        Authentication auth = new TestingAuthenticationToken("testuser", "password", "ROLE_USER");

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then
        assertThat(context.getUserId()).isEqualTo("testuser");
        assertThat(context.getRemoteIp()).isEqualTo("192.168.1.1");
        assertThat(context.getRequestPath()).isEqualTo("/api/users");
        assertThat(context.getHttpMethod()).isEqualTo("GET");
    }

    @Test
    @DisplayName("Should extract IP from X-Forwarded-For header")
    void shouldExtractIpFromXForwardedFor() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/data");
        request.setMethod("POST");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.50, 70.41.3.18");
        request.addHeader("User-Agent", "TestClient");

        Authentication auth = new TestingAuthenticationToken("proxyuser", "password", "ROLE_USER");

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then
        assertThat(context.getRemoteIp()).isEqualTo("203.0.113.50");
    }

    @Test
    @DisplayName("Should handle anonymous user")
    void shouldHandleAnonymousUser() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/public/info");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("User-Agent", "TestBrowser");

        Authentication auth = new TestingAuthenticationToken("anonymousUser", null);

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then
        assertThat(context.getUserId()).startsWith("anonymous:");
    }

    @Test
    @DisplayName("Should determine new session and new device flags")
    void shouldDetermineNewSessionAndDevice() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/dashboard");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("User-Agent", "NewBrowser/1.0");

        Authentication auth = new TestingAuthenticationToken("newuser", "password", "ROLE_USER");

        when(hcadDataStore.getSessionMetadata(any())).thenReturn(Collections.emptyMap());
        when(hcadDataStore.isDeviceRegistered(anyString(), anyString())).thenReturn(false);

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then
        assertThat(context.getIsNewSession()).isTrue();
        assertThat(context.getIsNewDevice()).isTrue();
    }

    @Test
    @DisplayName("Exception should return default HCADContext")
    void exception_shouldReturnDefaultContext() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/error");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.99");
        request.addHeader("User-Agent", "TestAgent");

        Authentication auth = new TestingAuthenticationToken("erroruser", "password", "ROLE_USER");

        when(hcadDataStore.getSessionMetadata(any()))
                .thenThrow(new RuntimeException("Redis connection failed"));

        // Simulate exception during enrichWithSessionInfo causing overall failure
        // The extractContext wraps in try-catch and returns fallback
        when(hcadDataStore.isDeviceRegistered(anyString(), anyString()))
                .thenThrow(new RuntimeException("Connection error"));
        when(hcadDataStore.isUserRegistered(anyString()))
                .thenThrow(new RuntimeException("Connection error"));
        when(hcadDataStore.getRecentRequestCount(anyString(), anyLong(), anyLong()))
                .thenThrow(new RuntimeException("Connection error"));
        when(securityContextDataStore.getLastRequestTime(anyString()))
                .thenThrow(new RuntimeException("Connection error"));

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then - should return a valid context (either enriched or fallback)
        assertThat(context).isNotNull();
        assertThat(context.getRequestPath()).isEqualTo("/api/error");
        assertThat(context.getHttpMethod()).isEqualTo("GET");
    }
}
