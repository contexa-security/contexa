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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Locale;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PasswordChangeController")
class PasswordChangeControllerTest {

    @Mock
    private PasswordChangeService passwordChangeService;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private MessageSource messageSource;

    private PasswordChangeController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        controller = new PasswordChangeController(passwordChangeService, passwordPolicyService, messageSource);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("showPasswordChangeForm")
    class ShowForm {

        @Test
        @DisplayName("should render password change form with username and policy")
        void success() throws Exception {
            PasswordPolicy policy = new PasswordPolicy();
            when(passwordPolicyService.getCurrentPolicy()).thenReturn(policy);

            mockMvc.perform(get("/contexa/password-change")
                            .param("username", "testuser"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/password-change"))
                    .andExpect(model().attribute("username", "testuser"))
                    .andExpect(model().attribute("policy", policy));
        }
    }

    @Nested
    @DisplayName("processPasswordChange")
    class ProcessChange {

        @Test
        @DisplayName("should redirect with error when user does not exist")
        void userNotFound() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.user.not.found"))
                    .when(passwordChangeService)
                    .changePassword("none", "pass", "newpass", "newpass");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "none")
                            .param("currentPassword", "pass")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "newpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=none"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.user.not.found"));
        }

        @Test
        @DisplayName("should redirect with error when current password does not match")
        void incorrectCurrentPassword() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.current.incorrect"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "wrong", "newpass", "newpass");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "wrong")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "newpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.current.incorrect"));
        }

        @Test
        @DisplayName("should redirect with error when new passwords do not match")
        void newPasswordMismatch() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.mismatch"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "correct", "newpass", "diffpass");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "diffpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.mismatch"));
        }

        @Test
        @DisplayName("should redirect with error when new password violates policy")
        void policyViolation() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.policy.violation", "Too short"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "correct", "weak", "weak");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "weak")
                            .param("confirmPassword", "weak"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.policy.violation"));
        }

        @Test
        @DisplayName("should redirect with error when password is reused")
        void passwordReused() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.reused"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "correct", "validpass", "validpass");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "validpass")
                            .param("confirmPassword", "validpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.reused"));
        }

        @Test
        @DisplayName("should change password and redirect to login on success")
        void success() throws Exception {
            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "validpass")
                            .param("confirmPassword", "validpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/mfa/login"))
                    .andExpect(flash().attribute("message", "msg.password.change.success"));

            verify(passwordChangeService).changePassword("testuser", "correct", "validpass", "validpass");
        }    }
}
