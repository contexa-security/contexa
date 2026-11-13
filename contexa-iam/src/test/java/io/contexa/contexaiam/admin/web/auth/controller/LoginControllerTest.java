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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DisplayName("LoginController")
class LoginControllerTest {

    @Test
    @DisplayName("should return login view name")
    void success() throws Exception {
        LoginController controller = new LoginController();
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        mockMvc.perform(get("/contexa/admin/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/login"));
    }

    /** Its second step only the sign-in's own page can take, and a form of the console posted to an address nothing served. */
    @Test
    @DisplayName("leads to the sign-in Contexa provides")
    void leadsToTheSignInContexaProvides() throws Exception {
        LoginController controller = new LoginController(LoginController.DEFAULT_LOGIN_PROCESSING_URL, () -> "/mfa/login");
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        mockMvc.perform(get("/contexa/admin/login"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/mfa/login"));
    }

    @Test
    @DisplayName("keeps its own form when no other sign-in provides the way in")
    void keepsItsOwnFormWhenNoOtherSignInProvidesTheWayIn() throws Exception {
        LoginController controller = new LoginController(LoginController.HOST_OWNED_LOGIN_PROCESSING_URL, () -> null);
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        mockMvc.perform(get("/contexa/admin/login"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("adminLoginProcessingUrl", LoginController.HOST_OWNED_LOGIN_PROCESSING_URL));
    }

    /** A flash attribute is spent on the redirects in between, so the change is said by a flag that goes along. */
    @Test
    @DisplayName("a changed password is said on the sign-in Contexa provides")
    void aChangedPasswordGoesAlongToTheSignIn() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(
                new LoginController(LoginController.DEFAULT_LOGIN_PROCESSING_URL, () -> "/mfa/login")).build();

        mockMvc.perform(get("/contexa/admin/login").param(LoginController.PASSWORD_CHANGED_PARAMETER, ""))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/mfa/login?passwordChanged"));
        mockMvc.perform(get("/contexa/admin/login"))
                .andExpect(redirectedUrl("/mfa/login"));
    }

    @Test
    @DisplayName("a changed password is said on the console's own form")
    void aChangedPasswordIsSaidOnTheOwnForm() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(
                new LoginController(LoginController.HOST_OWNED_LOGIN_PROCESSING_URL, () -> null)).build();

        mockMvc.perform(get("/contexa/admin/login").param(LoginController.PASSWORD_CHANGED_PARAMETER, ""))
                .andExpect(status().isOk())
                .andExpect(model().attribute("passwordChanged", true));
        mockMvc.perform(get("/contexa/admin/login"))
                .andExpect(model().attribute("passwordChanged", false));
    }
}
