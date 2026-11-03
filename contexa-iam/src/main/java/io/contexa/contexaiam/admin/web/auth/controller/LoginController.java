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

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    /** Where the console's sign-in form posts: Contexa's sign-in chain under CONTEXA_OWNED. */
    public static final String DEFAULT_LOGIN_PROCESSING_URL = "/login";

    /** Where it posts when the application owns sign-in (HOST_OWNED): the console's own chain. */
    public static final String HOST_OWNED_LOGIN_PROCESSING_URL = "/contexa/admin/login";

    private final String loginProcessingUrl;

    public LoginController() {
        this(DEFAULT_LOGIN_PROCESSING_URL);
    }

    public LoginController(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
    }

    @GetMapping("/contexa/admin/login")
    public String registerPage(Model model) {
        model.addAttribute("adminLoginProcessingUrl", loginProcessingUrl);
        return "contexa/admin/login";
    }

}
