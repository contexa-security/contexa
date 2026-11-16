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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Set;

/**
 * Console plan 5-2: the AI monitor's pages became the Zero Trust console's screens and its code is gone. An old address
 * or bookmark opens the screen that answers the same question: the overview, the decision trust (the AI decisions), the
 * operations (the analysis failures) and the adoption (the readiness), with its period when the console reads it.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AiMonitorController {

    /** The periods the Zero Trust console reads (ZeroTrustConsoleRange); another period opens its default week. */
    private static final Set<String> CONSOLE_PERIODS = Set.of("day", "week", "month", "quarter");

    @GetMapping({
            "/contexa/admin/ai-monitor",
            "/contexa/admin/ai-monitor/overview"
    })
    public String overviewPage(@RequestParam(required = false) String period, Authentication authentication) {
        requireAdmin(authentication);
        return consoleScreen("", period);
    }

    @GetMapping("/contexa/admin/ai-monitor/llm")
    public String llmPage(@RequestParam(required = false) String period, Authentication authentication) {
        requireAdmin(authentication);
        return consoleScreen("/trust", period);
    }

    @GetMapping({
            "/contexa/admin/ai-monitor/failures",
            "/contexa/admin/ai-monitor/operations"
    })
    public String failuresPage(@RequestParam(required = false) String period, Authentication authentication) {
        requireAdmin(authentication);
        return consoleScreen("/operations", period);
    }

    @GetMapping("/contexa/admin/ai-monitor/readiness")
    public String readinessPage(@RequestParam(required = false) String period, Authentication authentication) {
        requireAdmin(authentication);
        // the adoption screen reads its own observation span, not a period
        return consoleScreen("/adoption", null);
    }

    static String consoleScreen(String screen, String period) {
        String target = "/contexa/admin/zero-trust" + screen;
        String key = period == null ? null : period.trim().toLowerCase(Locale.ROOT);
        return "redirect:" + (key != null && CONSOLE_PERIODS.contains(key) ? target + "?period=" + key : target);
    }

    private void requireAdmin(Authentication authentication) {
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
