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
package io.contexa.contexaiam.admin.web.agent.controller;

import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationSource;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;

/**
 * The console's agent screens (A1-6): the list (AM-1) and one agent (AM-2). They show the registry's values as they
 * are and compute nothing. An agent is opened by query parameters because agent identifiers may hold any character.
 */
@Controller
@RequestMapping("/contexa/admin/agents")
@PreAuthorize("hasRole('ADMIN')")
public class AgentAdminController {

    /** The most agents one list shows; the latest seen come first. */
    static final int LIST_LIMIT = 500;

    private final AgentRegistry agentRegistry;
    private final MessageSource messageSource;

    public AgentAdminController(AgentRegistry agentRegistry, MessageSource messageSource) {
        this.agentRegistry = agentRegistry;
        this.messageSource = messageSource;
    }

    @GetMapping
    public String list(@RequestParam(value = "filter", required = false) String filter,
                       @RequestParam(value = "keyword", required = false) String keyword,
                       Model model) {
        String currentFilter = filter == null || filter.isBlank() ? "all" : filter.trim().toLowerCase(Locale.ROOT);
        List<AgentView> agents = agentRegistry.list(null, LIST_LIMIT).stream()
                .filter(byFilter(currentFilter))
                .filter(byKeyword(keyword))
                .map(AgentView::of)
                .toList();
        model.addAttribute("agents", agents);
        model.addAttribute("currentFilter", currentFilter);
        model.addAttribute("keyword", keyword);
        return "contexa/admin/agents";
    }

    @GetMapping("/detail")
    public String detail(@RequestParam("agentId") String agentId,
                         @RequestParam(value = "tenant", required = false) String tenant,
                         Model model,
                         RedirectAttributes redirectAttributes) {
        return agentRegistry.find(tenant == null || tenant.isBlank() ? null : tenant, agentId)
                .map(registration -> {
                    model.addAttribute("agent", AgentView.of(registration));
                    return "contexa/admin/agent-detail";
                })
                .orElseGet(() -> {
                    redirectAttributes.addFlashAttribute("errorMessage", messageSource.getMessage(
                            "admin.agents.not.found", new Object[]{agentId}, LocaleContextHolder.getLocale()));
                    return "redirect:/contexa/admin/agents";
                });
    }

    private static Predicate<AgentRegistration> byFilter(String filter) {
        return switch (filter) {
            case "active", "suspended", "deregistered" -> agent -> agent.status() != null
                    && agent.status().name().equalsIgnoreCase(filter);
            case "observed" -> agent -> agent.source() == AgentRegistrationSource.OBSERVED;
            case "registered" -> agent -> agent.source() == AgentRegistrationSource.LIFECYCLE;
            default -> agent -> true;
        };
    }

    private static Predicate<AgentRegistration> byKeyword(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            return agent -> true;
        }
        String needle = keyword.trim().toLowerCase(Locale.ROOT);
        return agent -> contains(agent.agentId(), needle) || contains(agent.displayName(), needle)
                || contains(agent.sponsorId(), needle) || contains(agent.clientId(), needle);
    }

    private static boolean contains(String value, String needle) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(needle);
    }
}
