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
package io.contexa.contexaiam.admin.promptquality.screen;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;

/**
 * The screens of the labelled cases (quality plan 3.2) and of measure and compare (quality plan 3.3, 3.8): their frame
 * for now, the title, the question the screen answers and the menu bar of the group. Every screen is an
 * administrator's, as the prompt version screens are.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityPageController {

    @GetMapping({PromptQualityScreens.CASES, PromptQualityScreens.CASES + "/"})
    public String casesPage(Model model, Authentication authentication) {
        return page("cases", model, authentication);
    }

    @GetMapping({PromptQualityScreens.MEASURE, PromptQualityScreens.MEASURE + "/"})
    public String measurePage(Model model, Authentication authentication) {
        return page("measure", model, authentication);
    }

    /** The screen's template; its menu entry (data-menu.sql) is "prompt-quality-" and the screen's name. */
    private String page(String screen, Model model, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", screen);
        model.addAttribute("activePage", "prompt-quality-" + screen);
        return PromptQualityScreens.TEMPLATES + screen;
    }

    private static void requireAdmin(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        boolean admin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
        if (!admin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}
