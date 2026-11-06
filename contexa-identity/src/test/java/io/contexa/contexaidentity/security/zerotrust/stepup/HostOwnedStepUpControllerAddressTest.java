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
package io.contexa.contexaidentity.security.zerotrust.stepup;

import io.contexa.contexaidentity.security.zerotrust.HostOwnedStepUp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A user who proved the address on record while the application shows another address stays on the step-up page: a
 * code went to the new address, and the page takes it.
 */
class HostOwnedStepUpControllerAddressTest {

    private final HostOwnedStepUpService service = mock(HostOwnedStepUpService.class);
    private final HostOwnedStepUpController controller = new HostOwnedStepUpController(service);

    @BeforeEach
    void signedIn() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", "x", "ROLE_USER"));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpServletRequest request(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", HostOwnedStepUp.STEP_UP_PATH + path);
        request.setContextPath("/app");
        return request;
    }

    private static HostOwnedStepUpService.Situation situation(boolean addressConfirmable) {
        return new HostOwnedStepUpService.Situation("alice", null, null, false, true, false, false, addressConfirmable,
                null);
    }

    @Test
    @DisplayName("a passed code with an address waiting stays on the step-up page")
    void aPassedCodeWithAnAddressWaiting() {
        MockHttpServletRequest request = request("/code/verify");
        when(service.verifyCode(eq(request), any(), eq("code"))).thenReturn(true);
        when(service.situation(eq(request), any())).thenReturn(situation(true));

        ResponseEntity<Map<String, Object>> answer = controller.verifyCode(request, "code");

        assertThat(answer.getBody()).containsEntry("verified", true)
                .containsEntry("redirectUrl", "/app" + HostOwnedStepUp.STEP_UP_PATH);
    }

    @Test
    @DisplayName("a passed code with nothing waiting goes back")
    void aPassedCodeWithNothingWaiting() {
        MockHttpServletRequest request = request("/code/verify");
        when(service.verifyCode(eq(request), any(), eq("code"))).thenReturn(true);
        when(service.situation(eq(request), any())).thenReturn(situation(false));

        assertThat(controller.verifyCode(request, "code").getBody()).containsEntry("redirectUrl", "/app/");
    }

    @Test
    @DisplayName("a passed passkey with an address waiting stays on the step-up page")
    @SuppressWarnings("unchecked")
    void aPassedPasskeyWithAnAddressWaiting() {
        MockHttpServletRequest request = request("/passkey/verify");
        when(service.verifyPasskey(eq(request), any(), any(PublicKeyCredential.class))).thenReturn(true);
        when(service.situation(eq(request), any())).thenReturn(situation(true));

        ResponseEntity<Map<String, Object>> answer = controller.verifyPasskey(request,
                "{\"id\":\"AQ\",\"rawId\":\"AQ\",\"type\":\"public-key\",\"clientExtensionResults\":{},\"response\":"
                        + "{\"authenticatorData\":\"AQ\",\"clientDataJSON\":\"e30\",\"signature\":\"AQ\"}}");

        assertThat(answer.getBody()).containsEntry("verified", true)
                .containsEntry("redirectUrl", "/app" + HostOwnedStepUp.STEP_UP_PATH);
    }

    @Test
    @DisplayName("the code of the new address confirms it and goes back")
    void theCodeOfTheNewAddress() {
        MockHttpServletRequest request = request("/address/verify");
        when(service.verifyAddressCode(eq(request), any(), eq("code"))).thenReturn(true);
        when(service.situation(eq(request), any())).thenReturn(situation(false));

        ResponseEntity<Map<String, Object>> answer = controller.verifyAddressCode(request, "code");

        assertThat(answer.getBody()).containsEntry("verified", true).containsEntry("redirectUrl", "/app/");
    }

    @Test
    @DisplayName("a refused code of the new address goes nowhere")
    void aRefusedCodeOfTheNewAddress() {
        assertThat(controller.verifyAddressCode(request("/address/verify"), "code").getStatusCode().value())
                .isEqualTo(400);
    }

    @Test
    @DisplayName("the new address is mailed its code again on request, at the step-up's pace")
    void theNewAddressIsMailedAgain() {
        MockHttpServletRequest request = request("/address/code");
        when(service.sendAddressCode(eq(request), any())).thenReturn(HostOwnedStepUpService.CodeSending.TOO_SOON);

        assertThat(controller.sendAddressCode(request).getBody()).containsEntry("sent", false)
                .containsEntry("wait", true);
    }

    @Test
    @DisplayName("an anonymous request is told to sign in")
    void anonymous() {
        SecurityContextHolder.clearContext();

        assertThat(controller.sendAddressCode(request("/address/code")).getStatusCode().value()).isEqualTo(401);
        assertThat(controller.verifyAddressCode(request("/address/verify"), "code").getStatusCode().value())
                .isEqualTo(401);
    }
}
