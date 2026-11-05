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

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedStepUp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A console session verifies itself inside the block list, the one place of the console open to it. */
class HostOwnedStepUpControllerConsoleTest {

    private final HostOwnedStepUpService service = mock(HostOwnedStepUpService.class);
    private final HostOwnedStepUpController controller = new HostOwnedStepUpController(service);

    @BeforeEach
    void signedIn() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("rcboss", "x", "ROLE_ADMIN"));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpServletRequest request(String path, boolean console) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setContextPath("/app");
        if (console) {
            ConsoleSession.mark(request);
        }
        return request;
    }

    @Test
    @DisplayName("the console's path lies inside the block list, so a BLOCK of the console session leaves it open")
    void theConsolesPathIsOnTheReleasePath() {
        MockHttpServletRequest console = new MockHttpServletRequest("GET", HostOwnedStepUp.CONSOLE_STEP_UP_PATH);
        ConsoleSession.mark(console);

        assertThat(ConsoleSession.onReleasePath(console)).isTrue();
        assertThat(HostOwnedStepUpController.class.getAnnotation(RequestMapping.class).value())
                .containsExactlyInAnyOrder(HostOwnedStepUp.STEP_UP_PATH, HostOwnedStepUp.CONSOLE_STEP_UP_PATH);
    }

    @Test
    @DisplayName("a request of the application's chain gets nothing from that path")
    void theApplicationGetsNothingFromThePath() {
        assertThat(ConsoleSession.onReleasePath(new MockHttpServletRequest("GET", HostOwnedStepUp.CONSOLE_STEP_UP_PATH)))
                .isFalse();
    }

    @Test
    @DisplayName("the console's page posts to the console's path and goes back to the block list")
    void theConsolesPage() {
        Model model = new ConcurrentModel();

        controller.page(request(HostOwnedStepUp.CONSOLE_STEP_UP_PATH, true), model);

        assertThat(model.getAttribute("stepUpBase")).isEqualTo("/app" + HostOwnedStepUp.CONSOLE_STEP_UP_PATH);
        assertThat(model.getAttribute("returnUrl")).isEqualTo("/app/contexa/admin/blacklist");
    }

    @Test
    @DisplayName("the application's page stays as it was")
    void theApplicationsPage() {
        Model model = new ConcurrentModel();

        controller.page(request(HostOwnedStepUp.STEP_UP_PATH, false), model);

        assertThat(model.getAttribute("stepUpBase")).isEqualTo("/app" + HostOwnedStepUp.STEP_UP_PATH);
        assertThat(model.getAttribute("returnUrl")).isEqualTo("/app/");
    }

    @Test
    @DisplayName("a code passed in the console goes back to the block list")
    void aPassedCodeGoesBackToTheList() {
        MockHttpServletRequest console = request(HostOwnedStepUp.CONSOLE_STEP_UP_PATH + "/code/verify", true);
        when(service.verifyCode(eq(console), any(), eq("code"))).thenReturn(true);

        ResponseEntity<Map<String, Object>> answer = controller.verifyCode(console, "code");

        assertThat(answer.getBody()).containsEntry("redirectUrl", "/app/contexa/admin/blacklist");
    }

    @Test
    @DisplayName("a code refused goes nowhere")
    void aRefusedCode() {
        MockHttpServletRequest console = request(HostOwnedStepUp.CONSOLE_STEP_UP_PATH + "/code/verify", true);

        assertThat(controller.verifyCode(console, "code").getStatusCode().value()).isEqualTo(400);
    }
}
