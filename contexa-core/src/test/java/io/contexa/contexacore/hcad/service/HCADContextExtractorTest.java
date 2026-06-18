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
package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacommon.hcad.official.OfficialContextRequestAttributes;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
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
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
    @DisplayName("Should ignore forwarded IP headers from untrusted remote address")
    void shouldIgnoreForwardedIpFromUntrustedRemoteAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/data");
        request.setMethod("POST");
        request.setRemoteAddr("198.51.100.9");
        request.addHeader("X-Forwarded-For", "203.0.113.50, 70.41.3.18");
        request.addHeader("User-Agent", "TestClient");

        TieredStrategyProperties.Security security = new TieredStrategyProperties.Security();
        security.setTrustedProxies(List.of("127.0.0.1"));
        extractor.setTrustedProxySecurity(security);

        Authentication auth = new TestingAuthenticationToken("proxyuser", "password", "ROLE_USER");

        HCADContext context = extractor.extractContext(request, auth);

        assertThat(context.getRemoteIp()).isEqualTo("198.51.100.9");
    }

    @Test
    @DisplayName("Should accept forwarded IP headers from configured trusted proxy")
    void shouldAcceptForwardedIpFromTrustedProxy() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/data");
        request.setMethod("POST");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "203.0.113.50, 70.41.3.18");
        request.addHeader("User-Agent", "TestClient");

        TieredStrategyProperties.Security security = new TieredStrategyProperties.Security();
        security.setTrustedProxies(List.of("127.0.0.1"));
        extractor.setTrustedProxySecurity(security);

        Authentication auth = new TestingAuthenticationToken("proxyuser", "password", "ROLE_USER");

        HCADContext context = extractor.extractContext(request, auth);

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
    @DisplayName("Should not let test page requests consume context-level new user session device state")
    void shouldNotConsumeContextNewnessForNonPromptRelevantRequests() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/admin/test/security");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("User-Agent", "Browser/1.0");

        Authentication auth = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");

        when(hcadDataStore.getSessionMetadata(anyString())).thenReturn(Collections.emptyMap());
        when(hcadDataStore.isDeviceRegistered(anyString(), anyString())).thenReturn(false);
        when(hcadDataStore.isUserRegistered(anyString())).thenReturn(false);

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then
        // ?뚯뒪???붾㈃ 吏꾩엯?대굹 ?곹깭 議고쉶??LLM ?낅젰??而⑦뀓?ㅽ듃瑜?留뚮뱾湲??꾪븳 business access媛 ?꾨땲??
        // ?ш린???좉퇋 ?ъ슜???몄뀡/?붾컮?댁뒪瑜??뚮え?대쾭由щ㈃ ?댄썑 泥?蹂댄샇 由ъ냼???묎렐?????댁긽 "泥??묎렐"?쇰줈 蹂댁씠吏 ?딅뒗??
        assertThat(context.getIsNewSession()).isTrue();
        assertThat(context.getIsNewDevice()).isTrue();
        assertThat(context.getIsNewUser()).isTrue();
        verify(hcadDataStore, never()).saveSessionMetadata(any(), any());
        verify(hcadDataStore, never()).registerDevice(anyString(), anyString());
        verify(hcadDataStore, never()).registerUser(anyString());
    }

    @Test
    @DisplayName("Should register new user session device only when the request is prompt-relevant protected access")
    void shouldRegisterContextNewnessOnlyForPromptRelevantProtectedRequests() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/admin/api/security-test/sensitive/resource-001");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("User-Agent", "Browser/1.0");

        Authentication auth = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");

        when(hcadDataStore.getSessionMetadata(anyString())).thenReturn(Collections.emptyMap());
        when(hcadDataStore.isDeviceRegistered(anyString(), anyString())).thenReturn(false);
        when(hcadDataStore.isUserRegistered(anyString())).thenReturn(false);

        // when
        HCADContext context = extractor.extractContext(request, auth);

        // then
        // ?ㅼ젣 蹂댄샇 由ъ냼???묎렐???뚮쭔 ?좉퇋???곹깭瑜??깅줉?댁빞 ?ㅼ쓬 蹂댄샇 由ъ냼???묎렐遺??false濡??꾩씠?쒕떎.
        assertThat(context.getIsNewSession()).isTrue();
        assertThat(context.getIsNewDevice()).isTrue();
        assertThat(context.getIsNewUser()).isTrue();
        verify(hcadDataStore).saveSessionMetadata(any(), any());
        verify(hcadDataStore).registerDevice(anyString(), anyString());
        verify(hcadDataStore).registerUser(anyString());
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

        // then - should return a valid context with conservative unknown defaults
        assertThat(context).isNotNull();
        assertThat(context.getRequestPath()).isEqualTo("/api/error");
        assertThat(context.getHttpMethod()).isEqualTo("GET");
        assertThat(context.getIsNewSession()).isFalse();
        assertThat(context.getIsNewDevice()).isFalse();
        assertThat(context.getIsNewUser()).isFalse();
        assertThat(context.getAdditionalAttributes())
                .containsEntry("sessionInfoUnavailable", true)
                .containsEntry("securityInfoUnavailable", true);
    }

    @Test
    @DisplayName("Should prefer explicit resource hints over generic path segments")
    void shouldPreferExplicitResourceHintsOverGenericPathSegments() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/admin/api/security-test/sensitive/self-sensitive-1");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.11");
        request.addHeader("User-Agent", "Browser/1.0");
        request.setAttribute("resourceId", "self-sensitive-1");
        request.setAttribute("resourceType", "sensitive");
        request.setAttribute("resourceBusinessLabel", "Sensitive Security Test Resource self-sensitive-1");

        Authentication auth = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");

        HCADContext context = extractor.extractContext(request, auth);

        assertThat(context.getResourceType()).isEqualTo("sensitive");
        assertThat(context.getIsSensitiveResource()).isFalse();
        assertThat(context.getAdditionalAttributes())
                .containsEntry("resourceId", "self-sensitive-1")
                .containsEntry("resourceType", "sensitive")
                .containsEntry("resourceBusinessLabel", "Sensitive Security Test Resource self-sensitive-1");
    }

    @Test
    @DisplayName("Should preserve tenant and organization scope as explicit official context fields")
    void shouldPreserveTenantAndOrganizationScope() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/admin/api/security-test/critical/resource-001");
        request.setMethod("GET");
        request.setRemoteAddr("10.0.0.11");
        request.addHeader("User-Agent", "Browser/1.0");
        request.addHeader("X-Contexa-Tenant-Id", "tenant-acme");
        request.addHeader("X-Contexa-Organization-Id", "org-finance");
        request.addHeader("X-Contexa-Org-Id", "org-finance-short");

        Authentication auth = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");

        HCADContext context = extractor.extractContext(request, auth);
        Map<String, Object> snapshot = OfficialContextRequestAttributes.snapshotFrom(context);

        assertThat(context.getAdditionalAttributes())
                .containsEntry("tenantId", "tenant-acme")
                .containsEntry("organizationId", "org-finance")
                .containsEntry("orgId", "org-finance-short");
        assertThat(snapshot)
                .containsEntry("tenantId", "tenant-acme")
                .containsEntry("organizationId", "org-finance")
                .containsEntry("orgId", "org-finance-short");
    }
}
