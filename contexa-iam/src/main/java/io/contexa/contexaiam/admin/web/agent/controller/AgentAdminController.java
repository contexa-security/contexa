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
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationViews.DelegationView;
import io.contexa.contexaiam.admin.web.agent.dto.AgentView;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import io.contexa.contexaiam.admin.web.common.ConsoleFault;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import java.util.HashMap;
import java.util.Map;

/**
 * The console's agent screens (A1-6): the list (AM-1) and one agent (AM-2). They show the registry's values as they
 * are and compute nothing. An agent is opened by query parameters because agent identifiers may hold any character.
 * On one agent an administrator quarantines, releases or removes what the agent learned (docs/agent A3-8), and reads
 * and revokes the delegations people gave it (docs/agent OC-1). Agents are registered with their OAuth2 client, and
 * retired, from here too (docs/agent OC-3).
 */
@Slf4j
@Controller
@RequestMapping("/contexa/admin/agents")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AgentAdminController {

    /** The most agents one list shows; the latest seen come first. */
    static final int LIST_LIMIT = 500;
    /** The most delegations read to count the ones that hold for each agent (A5-2). */
    static final int ACTIVE_DELEGATION_SCAN = 5000;
    /** The most delegations one agent's screen shows; the latest started come first. */
    static final int DELEGATION_LIMIT = 50;
    private static final String SECURITY_DECISION = "SECURITY_DECISION";

    private final AgentRegistry agentRegistry;
    private final MessageSource messageSource;
    private final AgentLearningAdminService learningService;
    private final AgentDelegationService delegationService;
    private final AgentProvisioning provisioning;
    private final Clock clock;
    /** docs/agent A5-5: the decision records the agent screens show; none without an audit store. */
    private AuditLogRepository decisionRecords;

    public AgentAdminController(AgentRegistry agentRegistry, MessageSource messageSource,
                                AgentLearningAdminService learningService, AgentDelegationService delegationService,
                                AgentProvisioning provisioning) {
        this(agentRegistry, messageSource, learningService, delegationService, provisioning, Clock.systemUTC());
    }

    AgentAdminController(AgentRegistry agentRegistry, MessageSource messageSource,
                         AgentLearningAdminService learningService, AgentDelegationService delegationService,
                         AgentProvisioning provisioning, Clock clock) {
        this.agentRegistry = agentRegistry;
        this.messageSource = messageSource;
        this.learningService = learningService;
        this.delegationService = delegationService;
        this.provisioning = provisioning != null ? provisioning : AgentProvisioning.unavailable();
        this.clock = clock;
    }

    /** docs/agent A5-5: the audit store whose decision records show each agent's latest decisions (AM-1, AM-2). */
    public void setDecisionRecords(AuditLogRepository decisionRecords) {
        this.decisionRecords = decisionRecords;
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
        model.addAttribute("latestDecisions", latestDecisions());
        model.addAttribute("activeDelegations", activeDelegations());
        model.addAttribute("currentFilter", currentFilter);
        model.addAttribute("keyword", keyword);
        model.addAttribute("provisioningAvailable", provisioning.available());
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
                    model.addAttribute("decisions", recentDecisions(registration.agentId()));
                    model.addAttribute("learningControllable", learningService.available());
                    model.addAttribute("learningQuarantined", learningService.quarantined(agentId, null));
                    model.addAttribute("provisioningAvailable", provisioning.available());
                    model.addAttribute("delegations", delegationService.list(registration.tenantId(), null,
                                    registration.agentId(), DELEGATION_LIMIT).stream()
                            .map(delegation -> DelegationView.of(delegation, clock.instant())).toList());
                    return "contexa/admin/agent-detail";
                })
                .orElseGet(() -> {
                    redirectAttributes.addFlashAttribute("errorMessage", messageSource.getMessage(
                            "admin.agents.not.found", new Object[]{agentId}, LocaleContextHolder.getLocale()));
                    return "redirect:/contexa/admin/agents";
                });
    }

    /**
     * docs/agent A5-2 (AM-1): how many delegations of people hold for each agent now, by agent ID; empty when they
     * cannot be read.
     */
    private Map<String, Integer> activeDelegations() {
        Map<String, Integer> active = new HashMap<>();
        try {
            Instant now = clock.instant();
            for (AgentDelegation delegation : delegationService.list(null, null, null, ACTIVE_DELEGATION_SCAN)) {
                if (delegation.validAt(now)) {
                    active.merge(delegation.agentId(), 1, Integer::sum);
                }
            }
        } catch (RuntimeException e) {
            log.error("The agents' delegations could not be read", e);
        }
        return active;
    }

    /** Each agent's latest decision, by agent ID; empty without an audit store or when it cannot be read. */
    private Map<String, String> latestDecisions() {
        Map<String, String> latest = new HashMap<>();
        if (decisionRecords == null) {
            return latest;
        }
        try {
            for (AuditLog record : decisionRecords
                    .findTop500ByAgentIdIsNotNullAndEventCategoryOrderByTimestampDesc(SECURITY_DECISION)) {
                latest.putIfAbsent(record.getAgentId(), record.getDecision());
            }
        } catch (RuntimeException e) {
            log.error("The agents' latest decisions could not be read", e);
        }
        return latest;
    }

    /** The agent's latest decision records; empty without an audit store or when they cannot be read. */
    private List<AuditLog> recentDecisions(String agentId) {
        if (decisionRecords == null) {
            return List.of();
        }
        try {
            return decisionRecords.findTop10ByAgentIdAndEventCategoryOrderByTimestampDesc(agentId,
                    SECURITY_DECISION);
        } catch (RuntimeException e) {
            log.error("The decisions of agent {} could not be read", agentId, e);
            return List.of();
        }
    }

    /** docs/agent A3-8: quarantines, releases or removes the learning of the agent, or of one of its delegations. */
    @PostMapping("/learning")
    public String learning(@RequestParam("agentId") String agentId,
                           @RequestParam(value = "tenant", required = false) String tenant,
                           @RequestParam(value = "delegationId", required = false) String delegationId,
                           @RequestParam("action") String action,
                           @RequestParam(value = "reason", required = false) String reason,
                           RedirectAttributes redirectAttributes) {
        try {
            AgentLearningAdminService.Action chosen = AgentLearningAdminService.Action.of(action);
            learningService.apply(chosen, agentId, delegationId, reason, currentAdmin());
            redirectAttributes.addFlashAttribute("message", messageSource.getMessage(
                    "admin.agents.learning.done." + chosen.name(), new Object[]{agentId},
                    LocaleContextHolder.getLocale()));
        } catch (RuntimeException e) {
            log.error("[AgentAdmin] Agent learning action failed: agentId={}, action={}", agentId, action, e);
            redirectAttributes.addFlashAttribute("errorMessage", messageSource.getMessage(
                    "admin.agents.learning.failed", new Object[]{ConsoleFault.textOf(e)}, LocaleContextHolder.getLocale()));
        }
        redirectAttributes.addAttribute("agentId", agentId);
        if (tenant != null && !tenant.isBlank()) {
            redirectAttributes.addAttribute("tenant", tenant);
        }
        return "redirect:/contexa/admin/agents/detail";
    }

    /** docs/agent OC-3: the registration form. */
    @GetMapping("/new")
    public String registrationForm(Model model) {
        model.addAttribute("provisioningAvailable", provisioning.available());
        return "contexa/admin/agent-register";
    }

    /**
     * docs/agent OC-3: registers the agent with its OAuth2 client (and its account) and shows the secrets once; the
     * page is never cached.
     */
    @PostMapping("/register")
    public String register(@RequestParam("agentId") String agentId,
                           @RequestParam(value = "displayName", required = false) String displayName,
                           @RequestParam(value = "agentType", required = false) String agentType,
                           @RequestParam(value = "sponsorId", required = false) String sponsorId,
                           @RequestParam(value = "tenant", required = false) String tenant,
                           @RequestParam(value = "clientId", required = false) String clientId,
                           @RequestParam(value = "scopes", required = false) String scopes,
                           @RequestParam(value = "ownToken", defaultValue = "false") boolean ownToken,
                           @RequestParam(value = "actsForPeople", defaultValue = "false") boolean actsForPeople,
                           @RequestParam(value = "tokenLifetimeMinutes", required = false) Long tokenLifetimeMinutes,
                           @RequestParam(value = "account", defaultValue = "false") boolean account,
                           @RequestParam(value = "accountGroups", required = false) String accountGroups,
                           Model model, HttpServletResponse response) {
        try {
            AgentProvisioning.Credentials credentials = provisioning.register(new AgentProvisioning.Registration(
                    blank(tenant), agentId, displayName, agentType, sponsorId, blank(clientId), words(scopes), ownToken,
                    actsForPeople, tokenLifetimeMinutes != null ? Duration.ofMinutes(tokenLifetimeMinutes) : null,
                    account, words(accountGroups)), currentAdmin());
            return credentials(credentials, model, response);
        } catch (RuntimeException e) {
            log.error("[AgentAdmin] Agent registration failed: agentId={}", agentId, e);
            model.addAttribute("provisioningAvailable", provisioning.available());
            model.addAttribute("errorMessage", messageSource.getMessage("admin.agents.register.failed",
                    new Object[]{ConsoleFault.textOf(e)}, LocaleContextHolder.getLocale()));
            return "contexa/admin/agent-register";
        }
    }

    /** docs/agent OC-3: gives the agent's client a new secret and shows it once. */
    @PostMapping("/manage/secret")
    public String rotateSecret(@RequestParam("agentId") String agentId,
                               @RequestParam(value = "tenant", required = false) String tenant,
                               Model model, HttpServletResponse response, RedirectAttributes redirectAttributes) {
        try {
            return credentials(provisioning.rotateSecret(blank(tenant), agentId, currentAdmin()), model, response);
        } catch (RuntimeException e) {
            return manageFailed(agentId, tenant, e, redirectAttributes);
        }
    }

    /** docs/agent OC-3: makes another person accountable for the agent. */
    @PostMapping("/manage/sponsor")
    public String transferSponsor(@RequestParam("agentId") String agentId,
                                  @RequestParam(value = "tenant", required = false) String tenant,
                                  @RequestParam(value = "sponsorId", required = false) String sponsorId,
                                  RedirectAttributes redirectAttributes) {
        try {
            provisioning.transferSponsor(blank(tenant), agentId, sponsorId, currentAdmin());
            return manageDone("admin.agents.manage.done.sponsor", agentId, tenant, redirectAttributes);
        } catch (RuntimeException e) {
            return manageFailed(agentId, tenant, e, redirectAttributes);
        }
    }

    /** docs/agent OC-3: deregisters the agent with the administrator's reason; its tokens are revoked. */
    @PostMapping("/manage/deregister")
    public String deregister(@RequestParam("agentId") String agentId,
                             @RequestParam(value = "tenant", required = false) String tenant,
                             @RequestParam(value = "reason", required = false) String reason,
                             RedirectAttributes redirectAttributes) {
        try {
            provisioning.deregister(blank(tenant), agentId, reason, currentAdmin());
            return manageDone("admin.agents.manage.done.deregister", agentId, tenant, redirectAttributes);
        } catch (RuntimeException e) {
            return manageFailed(agentId, tenant, e, redirectAttributes);
        }
    }

    /** docs/agent OC-3: removes the agent, its client, its tokens and its account for good. */
    @PostMapping("/manage/remove")
    public String remove(@RequestParam("agentId") String agentId,
                         @RequestParam(value = "tenant", required = false) String tenant,
                         RedirectAttributes redirectAttributes) {
        try {
            provisioning.remove(blank(tenant), agentId, currentAdmin());
            redirectAttributes.addFlashAttribute("message", messageSource.getMessage("admin.agents.manage.done.remove",
                    new Object[]{agentId}, LocaleContextHolder.getLocale()));
            return "redirect:/contexa/admin/agents";
        } catch (RuntimeException e) {
            return manageFailed(agentId, tenant, e, redirectAttributes);
        }
    }

    private String credentials(AgentProvisioning.Credentials credentials, Model model, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        model.addAttribute("credentials", credentials);
        model.addAttribute("agent", AgentView.of(credentials.registration()));
        return "contexa/admin/agent-credentials";
    }

    private String manageDone(String messageKey, String agentId, String tenant, RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("message", messageSource.getMessage(messageKey, new Object[]{agentId},
                LocaleContextHolder.getLocale()));
        return toDetail(agentId, tenant, redirectAttributes);
    }

    private String manageFailed(String agentId, String tenant, RuntimeException e,
                                RedirectAttributes redirectAttributes) {
        log.error("[AgentAdmin] Agent management failed: agentId={}", agentId, e);
        redirectAttributes.addFlashAttribute("errorMessage", messageSource.getMessage("admin.agents.manage.failed",
                new Object[]{ConsoleFault.textOf(e)}, LocaleContextHolder.getLocale()));
        return toDetail(agentId, tenant, redirectAttributes);
    }

    private static String toDetail(String agentId, String tenant, RedirectAttributes redirectAttributes) {
        redirectAttributes.addAttribute("agentId", agentId);
        if (tenant != null && !tenant.isBlank()) {
            redirectAttributes.addAttribute("tenant", tenant);
        }
        return "redirect:/contexa/admin/agents/detail";
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static List<String> words(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split("[,\\s]+")).filter(word -> !word.isBlank()).toList();
    }

    /**
     * docs/agent OC-1: revokes a delegation of the agent at once, with the administrator's reason. An agent holding an
     * administrator's token is refused, as the admin API refuses it.
     */
    @PostMapping("/delegations/revoke")
    public String revokeDelegation(@RequestParam("agentId") String agentId,
                                   @RequestParam(value = "tenant", required = false) String tenant,
                                   @RequestParam("delegationId") String delegationId,
                                   @RequestParam(value = "reason", required = false) String reason,
                                   HttpServletRequest request, RedirectAttributes redirectAttributes) {
        if (AgentDelegationApiController.fromAnAgent(request)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An agent cannot revoke a delegation");
        }
        try {
            boolean revoked = delegationService.revokeAsAdministrator(currentAdmin(), delegationId, reason)
                    .isPresent();
            redirectAttributes.addFlashAttribute(revoked ? "message" : "errorMessage", messageSource.getMessage(
                    revoked ? "admin.agents.delegations.revoked" : "admin.agents.delegations.not.found",
                    new Object[]{delegationId}, LocaleContextHolder.getLocale()));
        } catch (RuntimeException e) {
            log.error("[AgentAdmin] Delegation revocation failed: agentId={}, delegationId={}", agentId,
                    delegationId, e);
            redirectAttributes.addFlashAttribute("errorMessage", messageSource.getMessage(
                    "admin.agents.delegations.failed", new Object[]{ConsoleFault.textOf(e)},
                    LocaleContextHolder.getLocale()));
        }
        redirectAttributes.addAttribute("agentId", agentId);
        if (tenant != null && !tenant.isBlank()) {
            redirectAttributes.addAttribute("tenant", tenant);
        }
        return "redirect:/contexa/admin/agents/detail";
    }

    private static String currentAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new IllegalStateException("No administrator is signed in");
        }
        return authentication.getName();
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
