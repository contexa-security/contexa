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

import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.function.Supplier;

/**
 * The console's agent stops (docs/agent A5-3, AM-4), the agents tab of the block list: the agents suspended, the agents
 * stopped while they acted for a person and why, their release, the kill switch and the history.
 */
@Slf4j
@Controller
@RequestMapping("/contexa/admin/blacklist/agents")
@PreAuthorize("hasRole('ADMIN')")
public class AgentStopController {

    private static final String REDIRECT = "redirect:/contexa/admin/blacklist/agents";

    private final AgentContainmentAdminService stops;
    private final MessageSource messageSource;

    public AgentStopController(AgentContainmentAdminService stops, MessageSource messageSource) {
        this.stops = stops;
        this.messageSource = messageSource;
    }

    @GetMapping
    public String stops(Model model) {
        model.addAttribute("activePage", "blacklist");
        model.addAttribute("available", stops.available());
        model.addAttribute("suspendedAgents", stops.suspendedAgents());
        model.addAttribute("stoppedDelegations", stops.stoppedDelegations());
        model.addAttribute("narrowedAgents", stops.narrowedAgents());
        model.addAttribute("history", stops.history());
        model.addAttribute("notices", stops.notices());
        return "contexa/admin/agent-stops";
    }

    @PostMapping("/release-delegation")
    public String releaseDelegation(@RequestParam("userId") String userId, @RequestParam("agentId") String agentId,
                                    @RequestParam("reason") String reason, Authentication authentication,
                                    RedirectAttributes redirectAttributes) {
        return act(redirectAttributes, reason, () -> {
            stops.releaseDelegatedAgent(userId, agentId, admin(authentication), reason.trim());
            return message("admin.agent.stops.released", agentId);
        });
    }

    @PostMapping("/release-agent")
    public String releaseAgent(@RequestParam(value = "tenant", required = false) String tenant,
                               @RequestParam("agentId") String agentId, @RequestParam("reason") String reason,
                               Authentication authentication, RedirectAttributes redirectAttributes) {
        return act(redirectAttributes, reason, () -> {
            if (!stops.releaseAgent(tenant, agentId, admin(authentication), reason.trim())) {
                throw new IllegalArgumentException("The agent is not registered: " + agentId);
            }
            return message("admin.agent.stops.released", agentId);
        });
    }

    @PostMapping("/kill-switch")
    public String killSwitch(@RequestParam(value = "tenant", required = false) String tenant,
                             @RequestParam(value = "agentType", required = false) String agentType,
                             @RequestParam("reason") String reason, Authentication authentication,
                             RedirectAttributes redirectAttributes) {
        return act(redirectAttributes, reason, () -> message("admin.agent.stops.kill.switch.done",
                stops.killSwitch(tenant, agentType, admin(authentication), reason.trim()).size()));
    }

    @PostMapping("/kill-switch/release")
    public String releaseKillSwitch(@RequestParam(value = "tenant", required = false) String tenant,
                                    @RequestParam(value = "agentType", required = false) String agentType,
                                    @RequestParam("reason") String reason, Authentication authentication,
                                    RedirectAttributes redirectAttributes) {
        return act(redirectAttributes, reason, () -> message("admin.agent.stops.kill.switch.released",
                stops.releaseKillSwitch(tenant, agentType, admin(authentication), reason.trim()).size()));
    }

    /** Runs the action when a reason is given; its message, or why it failed, is shown on the stops. */
    private String act(RedirectAttributes redirectAttributes, String reason, Supplier<String> action) {
        if (reason == null || reason.isBlank()) {
            redirectAttributes.addFlashAttribute("errorMessage", message("admin.agent.stops.reason.placeholder"));
            return REDIRECT;
        }
        try {
            redirectAttributes.addFlashAttribute("message", action.get());
        } catch (IllegalArgumentException | IllegalStateException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        } catch (RuntimeException e) {
            log.error("Agent stop action failed", e);
            redirectAttributes.addFlashAttribute("errorMessage", message("admin.agent.stops.failed"));
        }
        return REDIRECT;
    }

    private String message(String key, Object... arguments) {
        return messageSource.getMessage(key, arguments, key, LocaleContextHolder.getLocale());
    }

    private static String admin(Authentication authentication) {
        return authentication != null ? authentication.getName() : "unknown";
    }
}
