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
package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.view.AbstractView;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * PR-57: the screens of a decision send the browser to the address in their query string, so only a path of this
 * application may get through, however it is written. The values are what the controller receives, that is, after the
 * one decoding of the servlet container.
 */
class ZeroTrustPageControllerTest {

    private static final String ANALYSIS_PENDING = "/contexa/zero-trust/analysis-pending";
    private static final String CHALLENGE_REQUIRED = "/contexa/zero-trust/challenge-required";

    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new ZeroTrustPageController(
                    mock(BlockMfaStateStore.class), mock(BlockedUserService.class), mock(SecurityZeroTrustProperties.class)))
            .setSingleView(new AbstractView() {
                @Override
                protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
                                                       HttpServletResponse response) {
                }
            })
            .build();

    private final BlockMfaStateStore verifications = mock(BlockMfaStateStore.class);
    private final ZeroTrustPageController blockedScreen = new ZeroTrustPageController(verifications,
            mock(BlockedUserService.class), mock(SecurityZeroTrustProperties.class));

    private boolean blockListOffered(String... authorities) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/zero-trust/blocked");
        request.setRequestedSessionId("session");
        when(verifications.isVerified("rcboss")).thenReturn(true);
        when(verifications.isVerified("rcboss", SessionFingerprintUtil.verificationContext(request))).thenReturn(true);
        Model model = new ConcurrentModel();
        blockedScreen.blocked(new TestingAuthenticationToken("rcboss", "x", authorities), model, request);
        return Boolean.TRUE.equals(model.getAttribute("blockListOpen"));
    }

    @Test
    @DisplayName("The screen of a BLOCK leads an administrator who passed MFA here to the block list")
    void theAdministratorIsLedToTheList() {
        assertThat(blockListOffered("ROLE_ADMIN")).isTrue();
    }

    @Test
    @DisplayName("as a session reads the account under the BLOCK, with the authority of the BLOCK alone")
    void theAdministratorOfANarrowedSessionIsLedToTheList() {
        UnifiedCustomUserDetails account = new UnifiedCustomUserDetails(UserDto.builder().username("rcboss").build(),
                Set.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/zero-trust/blocked");
        request.setRequestedSessionId("session");
        when(verifications.isVerified("rcboss", SessionFingerprintUtil.verificationContext(request))).thenReturn(true);
        Model model = new ConcurrentModel();

        blockedScreen.blocked(new TestingAuthenticationToken(account, "x", "ROLE_BLOCKED"), model, request);

        assertThat(model.getAttribute("blockListOpen")).isEqualTo(true);
    }

    @Test
    @DisplayName("A user who is no administrator is not")
    void aPlainUserIsNot() {
        assertThat(blockListOffered("ROLE_USER")).isFalse();
    }

    @Test
    @DisplayName("A verification of another session leads nowhere")
    void anotherSessionIsNot() {
        when(verifications.isVerified("rcboss")).thenReturn(true);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/contexa/zero-trust/blocked");
        Model model = new ConcurrentModel();

        blockedScreen.blocked(new TestingAuthenticationToken("rcboss", "x", "ROLE_ADMIN"), model, request);

        assertThat(model.getAttribute("blockListOpen")).isEqualTo(false);
    }

    @Test
    @DisplayName("Where the application owns sign-in the console has a sign-in of its own, and nothing is offered here")
    void hostOwnedOffersNothing() {
        blockedScreen.setBlockListOffered(false);

        assertThat(blockListOffered("ROLE_ADMIN")).isFalse();
    }

    private static Stream<String> addressesOutsideTheApplication() {
        return Stream.of(
                "https://evil.example/",
                "http://evil.example",
                "HTTPS://evil.example",
                "//evil.example",
                "//evil.example/orders",
                "///evil.example",
                "/\\evil.example",
                "\\\\evil.example",
                "\\/evil.example",
                "/\t/evil.example",
                "/\n/evil.example",
                "/\r/evil.example",
                " /evil.example",
                "javascript:alert(1)",
                "JaVaScRiPt:alert(1)",
                "java\tscript:alert(1)",
                "data:text/html,evil",
                "evil.example",
                "%2F%2Fevil.example",
                "/%2Fevil.example",
                "/%2fevil.example",
                "/%5Cevil.example",
                "/%5cevil.example",
                "/%09/evil.example",
                "/%0a/evil.example",
                "/%252Fevil.example",
                "/%25252Fevil.example",
                "/%2509/evil.example",
                "/%255Cevil.example",
                "/../evil",
                "/orders/../../evil",
                "/%2e%2e/evil",
                "/%252e%252e/evil",
                "/orders/..%2f..%2fevil",
                "/..;/evil",
                "/%00",
                "/orders%0d%0aSet-Cookie:%20a=b");
    }

    @ParameterizedTest
    @MethodSource("addressesOutsideTheApplication")
    @DisplayName("The analysis screen returns to the application's root instead of an address outside it")
    void analysisPendingRefusesAddressesOutsideTheApplication(String returnUrl) throws Exception {
        mvc.perform(get(ANALYSIS_PENDING).param("returnUrl", returnUrl))
                .andExpect(status().isOk())
                .andExpect(model().attribute("returnUrl", "/"));
    }

    @ParameterizedTest
    @MethodSource("addressesOutsideTheApplication")
    @DisplayName("The challenge notice leads to the factor selection instead of an address outside the application")
    void challengeRequiredRefusesAddressesOutsideTheApplication(String mfaUrl) throws Exception {
        mvc.perform(get(CHALLENGE_REQUIRED).param("mfaUrl", mfaUrl))
                .andExpect(status().isOk())
                .andExpect(model().attribute("mfaUrl", "/mfa/select-factor"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/orders", "/orders/42", "/orders/42/", "/orders/a%20b", "/orders?tab=open#top",
            "/orders?next=https://elsewhere.example/&path=%2F%2Fx", "/.well-known/x", "/@team/orders"})
    @DisplayName("A path of the application reaches both screens unchanged")
    void aPathOfTheApplicationIsKept(String path) throws Exception {
        mvc.perform(get(ANALYSIS_PENDING).param("returnUrl", path))
                .andExpect(model().attribute("returnUrl", path));
        mvc.perform(get(CHALLENGE_REQUIRED).param("mfaUrl", path))
                .andExpect(model().attribute("mfaUrl", path));
    }

    @Test
    @DisplayName("The CHALLENGE notice of an application without an MFA flow offers the sign-out, not a step-up")
    void theNoticeWithoutAStepUpOffersTheSignOut() throws Exception {
        mvc.perform(get(CHALLENGE_REQUIRED).param("stepUp", "none"))
                .andExpect(model().attribute("stepUpOffered", false));
        mvc.perform(get(CHALLENGE_REQUIRED))
                .andExpect(model().attribute("stepUpOffered", true));
    }

    @Test
    @DisplayName("Without a value the screens fall back to their own destination")
    void aMissingValueFallsBack() throws Exception {
        mvc.perform(get(ANALYSIS_PENDING)).andExpect(model().attribute("returnUrl", "/"));
        mvc.perform(get(CHALLENGE_REQUIRED)).andExpect(model().attribute("mfaUrl", "/mfa/select-factor"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/app", "/app/", "/app/orders", "/app/orders?tab=open"})
    @DisplayName("Under a context path a path of the application is kept")
    void aPathUnderTheContextPathIsKept(String path) throws Exception {
        mvc.perform(get("/app" + ANALYSIS_PENDING).contextPath("/app").param("returnUrl", path))
                .andExpect(model().attribute("returnUrl", path));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/orders", "/application/orders", "/app/../other", "/app/%2e%2e/other", "/app/..;/other",
            "https://evil.example/"})
    @DisplayName("Under a context path another application of the same server is outside the application")
    void aPathBesideTheContextPathIsRefused(String path) throws Exception {
        mvc.perform(get("/app" + ANALYSIS_PENDING).contextPath("/app").param("returnUrl", path))
                .andExpect(model().attribute("returnUrl", "/app/"));
        mvc.perform(get("/app" + CHALLENGE_REQUIRED).contextPath("/app").param("mfaUrl", path))
                .andExpect(model().attribute("mfaUrl", "/app/mfa/select-factor"));
    }

    @Test
    @DisplayName("The analysis screen's script goes where the server said, without decoding the value a second time")
    void theScriptDoesNotDecodeTheAddressAgain() throws Exception {
        String script = new ClassPathResource("static/contexa/js/zero-trust/analysis-pending.js")
                .getContentAsString(StandardCharsets.UTF_8);

        // consoleUrl adds the context path a root-relative address lacks and leaves one that has it, decoding nothing
        assertThat(script).contains("window.location.href = consoleUrl(returnUrl);").doesNotContain("decodeURIComponent");
    }
}
