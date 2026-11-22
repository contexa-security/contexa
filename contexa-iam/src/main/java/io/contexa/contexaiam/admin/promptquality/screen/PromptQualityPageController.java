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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleMessages;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;

/**
 * The screens of the labelled cases (quality plan 3.2) and of measure and compare (quality plan 3.3, 3.8): the frame of
 * each view, its title, the question it answers, the menu bar of the group, the addresses its script reads and the
 * words it shows. The views of a screen are drawn by its script from the screen's JSON. Every screen is an
 * administrator's, as the prompt version screens are.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityPageController {

    /** The JSON of the labelled cases. */
    static final String CASES_API = "/contexa/admin/api/prompt-quality/cases";
    /** The JSON of measure and compare. */
    static final String MEASURE_API = "/contexa/admin/api/prompt-quality/measure";
    /** The JSON of the prompt versions, which the trials, the confirmation of "use for decisions" and the canary read. */
    static final String VERSIONS_API = "/contexa/admin/api/prompt-quality/versions";
    /**
     * The words the scripts of the screens read: their own, the version screens' (the trials, the confirmation and
     * the notices they share), the decision actions, the units, the filter box's and the reason codes an answer cites.
     */
    static final String[] MESSAGE_PREFIXES = {"pqa.", "pv.", "zt.console.ui.action.", "zt.console.ui.unit.",
            "zt.console.ui.decisions.filter", "zt.console.reasonCode."};

    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    /** @param objectMapper Contexa's own JSON writer, for the words of the screens */
    public PromptQualityPageController(MessageSource messages, ObjectMapper objectMapper) {
        this.messages = messages;
        this.objectMapper = objectMapper;
    }

    // ----- the labelled cases -----

    @GetMapping({PromptQualityScreens.CASES, PromptQualityScreens.CASES + "/"})
    public String casesPage(Model model, Locale locale, Authentication authentication) {
        return page("cases", "list", model, locale, authentication);
    }

    @GetMapping(PromptQualityScreens.CASES + "/{key:[A-Za-z0-9._-]+}")
    public String casePage(@PathVariable String key, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("caseKey", key);
        return page("cases", "detail", model, locale, authentication);
    }

    // ----- measure and compare -----

    @GetMapping({PromptQualityScreens.MEASURE, PromptQualityScreens.MEASURE + "/"})
    public String measurePage(Model model, Locale locale, Authentication authentication) {
        return page("measure", "runs", model, locale, authentication);
    }

    @GetMapping(PromptQualityScreens.MEASURE + "/{id:\\d+}")
    public String runPage(@PathVariable long id, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("measureId", id);
        return page("measure", "run", model, locale, authentication);
    }

    /** Two versions: the candidate and the version it is compared with, else the latest candidate and the one in use. */
    @GetMapping(PromptQualityScreens.MEASURE + "/compare")
    public String comparePage(@RequestParam(required = false) Integer candidate,
                              @RequestParam(required = false) Integer current, Model model, Locale locale,
                              Authentication authentication) {
        model.addAttribute("candidate", candidate);
        model.addAttribute("current", current);
        return page("measure", "compare", model, locale, authentication);
    }

    /** The result of a measurement on the latest sealed decisions: a trial of the prompt versions (plan 3.10). */
    @GetMapping(PromptQualityScreens.MEASURE + "/trials/{id:\\d+}")
    public String trialPage(@PathVariable long id, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("trialId", id);
        return page("measure", "trial", model, locale, authentication);
    }

    /** The screen's template; its menu entry (data-menu.sql) is "prompt-quality-" and the screen's name. */
    private String page(String screen, String view, Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", screen);
        model.addAttribute("view", view);
        model.addAttribute("activePage", "prompt-quality-" + screen);
        model.addAttribute("apiBase", "cases".equals(screen) ? CASES_API : MEASURE_API);
        model.addAttribute("versionsApi", VERSIONS_API);
        model.addAttribute("versionsPages", PromptQualityScreens.VERSIONS);
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper,
                MESSAGE_PREFIXES));
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
