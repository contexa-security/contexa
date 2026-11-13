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
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.function.Supplier;

@Controller
public class LoginController {

    /** Where the console's sign-in form posts: Contexa's sign-in chain under CONTEXA_OWNED. */
    public static final String DEFAULT_LOGIN_PROCESSING_URL = "/login";

    /** Where it posts when the application owns sign-in (HOST_OWNED): the console's own chain. */
    public static final String HOST_OWNED_LOGIN_PROCESSING_URL = "/contexa/admin/login";

    /** The flag a changed password comes with, so the sign-in it leads to says the password was changed. */
    public static final String PASSWORD_CHANGED_PARAMETER = "passwordChanged";

    private final String loginProcessingUrl;
    private final Supplier<String> signInPage;

    public LoginController() {
        this(DEFAULT_LOGIN_PROCESSING_URL);
    }

    public LoginController(String loginProcessingUrl) {
        this(loginProcessingUrl, () -> null);
    }

    /**
     * @param signInPage the page of the sign-in Contexa provides, read at each request because the sign-in is built after this
     *                   bean; null when the console's own form is the way in
     */
    public LoginController(String loginProcessingUrl, Supplier<String> signInPage) {
        this.loginProcessingUrl = loginProcessingUrl;
        this.signInPage = signInPage;
    }

    @GetMapping("/contexa/admin/login")
    public String registerPage(@RequestParam(name = PASSWORD_CHANGED_PARAMETER, required = false) String passwordChanged,
                               Model model) {
        String page = signInPage.get();
        if (StringUtils.hasText(page)) {
            // The sign-in page is another page: the flag goes along, where a flash attribute would be spent on the way.
            return "redirect:" + page + (passwordChanged != null
                    ? (page.contains("?") ? "&" : "?") + PASSWORD_CHANGED_PARAMETER : "");
        }
        model.addAttribute("passwordChanged", passwordChanged != null);
        model.addAttribute("adminLoginProcessingUrl", loginProcessingUrl);
        return "contexa/admin/login";
    }

}
