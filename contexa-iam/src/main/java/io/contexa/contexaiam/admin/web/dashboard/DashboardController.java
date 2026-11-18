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
package io.contexa.contexaiam.admin.web.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DashboardView;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleMessages;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Objects;

/**
 * The admin dashboard (plan step 9, N1): its page and the JSON its script draws. The page carries the words of the
 * dashboard and of the Zero Trust console it reuses; the numbers come from {@code /contexa/admin/api/dashboard}. Both
 * are an administrator's, checked on each call as well as by the method security, as the Zero Trust console does.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class DashboardController {

    static final String API = "/contexa/admin/api/dashboard";
    /** The words the dashboard's script reads: its own, the console's, and the names of the combining algorithms. */
    static final String[] MESSAGE_PREFIXES = {"dashboard.ui.", "zt.console.", "admin.system.settings.combining.algorithm."};

    private final DashboardService dashboardService;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    public DashboardController(DashboardService dashboardService, MessageSource messages,
                               @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        this.dashboardService = Objects.requireNonNull(dashboardService, "dashboardService");
        this.messages = messages;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    @GetMapping({"/contexa/admin", "/contexa/admin/", "/contexa/admin/dashboard"})
    public String dashboard(Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("activePage", "dashboard");
        model.addAttribute("apiBase", API);
        model.addAttribute("screen", "dashboard");
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper,
                MESSAGE_PREFIXES));
        return "contexa/admin/dashboard";
    }

    @ResponseBody
    @GetMapping(API)
    public DashboardView data(@RequestParam(required = false) String period, Locale locale,
                              Authentication authentication) {
        requireAdmin(authentication);
        try {
            return dashboardService.dashboard(period, locale);
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
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
