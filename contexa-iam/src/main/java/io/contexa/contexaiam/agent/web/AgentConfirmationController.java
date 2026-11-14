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
package io.contexa.contexaiam.agent.web;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegations;
import io.contexa.contexacore.autonomous.agent.AgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.Temporal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The pages a person confirms an agent's request on (docs/agent A5-2, AC-1~AC-3): the person's confirmations and
 * notices, the confirmation of one request (what was delegated, what the agent asks, what differs and why Contexa
 * asks, with approve, refuse and report) and, once decided, its result with the authorization it was recorded as.
 * Only the person the confirmation is for decides it, in their own session: an agent's request is refused here even
 * when it carries the person's token.
 */
@Slf4j
@Controller
@RequestMapping("/contexa/agent-confirmations")
@PreAuthorize("isAuthenticated()")
public class AgentConfirmationController {

    private static final String PAGE = "redirect:/contexa/agent-confirmations/";
    static final int LIST_LIMIT = 50;

    private final AgentConfirmationService confirmations;
    private final MessageSource messageSource;
    private DelegationRegistry delegations;
    private AuditLogRepository decisionRecords;
    private AgentNoticeStore notices;
    private AgentContainmentAdminService stops;

    public AgentConfirmationController(AgentConfirmationService confirmations, MessageSource messageSource) {
        this.confirmations = confirmations;
        this.messageSource = messageSource;
    }

    public void setDelegations(@Nullable DelegationRegistry delegations) {
        this.delegations = delegations;
    }

    public void setDecisionRecords(@Nullable AuditLogRepository decisionRecords) {
        this.decisionRecords = decisionRecords;
    }

    public void setNotices(@Nullable AgentNoticeStore notices) {
        this.notices = notices;
    }

    /** docs/agent A5-3: the stops of agents, which their accountable person may release too. */
    public void setStops(@Nullable AgentContainmentAdminService stops) {
        this.stops = stops;
    }

    /** AC-1: the person's confirmations and the notices about their agents. */
    @GetMapping
    public String list(Authentication authentication, HttpServletRequest request, Model model) {
        String person = person(authentication, request);
        model.addAttribute("confirmations", confirmations.forRecipient(person, LIST_LIMIT));
        model.addAttribute("notices", notices != null ? notices.forRecipient(person, LIST_LIMIT) : List.of());
        model.addAttribute("stoppedAgents", stoppedAgents(person));
        model.addAttribute("releasable", stops != null && stops.available());
        return "contexa/agent-confirmations";
    }

    /**
     * The accountable person releases their stopped agent (docs/agent A5-3, AM-4: a release needs the accountable
     * person or an administrator), with a reason that the release record keeps.
     */
    @PostMapping("/stops/release")
    public String release(@RequestParam("kind") String kind, @RequestParam("agentId") String agentId,
                          @RequestParam("reason") String reason, Authentication authentication,
                          HttpServletRequest request, RedirectAttributes redirectAttributes) {
        String person = person(authentication, request);
        if (!StringUtils.hasText(reason)) {
            redirectAttributes.addFlashAttribute("errorMessage", message("agent.confirmations.release.reason"));
            return "redirect:/contexa/agent-confirmations";
        }
        Optional<StoppedAgent> stopped = stoppedAgents(person).stream()
                .filter(agent -> agent.kind().equals(kind) && agent.agentId().equals(agentId))
                .findFirst();
        if (stopped.isEmpty() || stopped.get().killSwitch() || stops == null || !stops.available()) {
            redirectAttributes.addFlashAttribute("errorMessage", message("agent.confirmations.release.refused"));
            return "redirect:/contexa/agent-confirmations";
        }
        try {
            if ("DELEGATED".equals(kind)) {
                stops.releaseDelegatedAgent(person, agentId, person, reason.trim());
            } else {
                stops.releaseAgent(stopped.get().tenantId(), agentId, person, reason.trim());
            }
            redirectAttributes.addFlashAttribute("message", message("agent.confirmations.released"));
        } catch (IllegalArgumentException | IllegalStateException e) {
            redirectAttributes.addFlashAttribute("errorMessage", message("agent.confirmations.release.refused"));
        }
        return "redirect:/contexa/agent-confirmations";
    }

    /** The person's agents that are stopped, the ones that acted for them and the ones they sponsor. */
    private List<StoppedAgent> stoppedAgents(String person) {
        if (stops == null) {
            return List.of();
        }
        List<StoppedAgent> stopped = new ArrayList<>();
        try {
            stops.stoppedDelegations().stream()
                    .filter(stop -> person.equals(stop.userId()))
                    .forEach(stop -> stopped.add(new StoppedAgent("DELEGATED", stop.agentId(), null, stop.stoppedAt(),
                            stop.reason(), false)));
            stops.suspendedAgents().stream()
                    .filter(agent -> person.equals(agent.sponsorId()))
                    .forEach(agent -> stopped.add(new StoppedAgent("AUTONOMOUS", agent.agentId(), agent.tenantId(),
                            null, agent.statusReason(), agent.statusReason() != null
                            && agent.statusReason().startsWith(AgentContainmentService.KILL_SWITCH_REASON))));
        } catch (RuntimeException e) {
            log.error("The person's stopped agents could not be read", e);
        }
        return stopped;
    }

    /** AC-2 while the request waits, AC-3 once decided. */
    @GetMapping("/{id}")
    public String confirmation(@PathVariable("id") String id, Authentication authentication,
                               HttpServletRequest request, Model model) {
        String person = person(authentication, request);
        AgentConfirmation confirmation = confirmations.status(id)
                .filter(found -> found.recipientId().equals(person))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        model.addAttribute("confirmation", confirmation);
        model.addAttribute("delegation", delegation(confirmation).orElse(null));
        AuditLog decision = decisionRecord(confirmation);
        model.addAttribute("decision", decision);
        model.addAttribute("riskFacts", decision != null && StringUtils.hasText(decision.getRiskState())
                ? Arrays.stream(decision.getRiskState().split(",\\s*")).filter(StringUtils::hasText).toList()
                : List.of());
        model.addAttribute("pending", confirmation.status() == AgentConfirmation.Status.PENDING);
        return "contexa/agent-confirmation";
    }

    @PostMapping("/{id}/approve")
    public String approve(@PathVariable("id") String id, @RequestParam(value = "note", required = false) String note,
                          Authentication authentication, HttpServletRequest request,
                          RedirectAttributes redirectAttributes) {
        String person = person(authentication, request);
        return decide(id, redirectAttributes, () -> confirmations.approve(id, person, note),
                "agent.confirmation.approved");
    }

    @PostMapping("/{id}/reject")
    public String reject(@PathVariable("id") String id, @RequestParam(value = "note", required = false) String note,
                         Authentication authentication, HttpServletRequest request,
                         RedirectAttributes redirectAttributes) {
        String person = person(authentication, request);
        return decide(id, redirectAttributes, () -> confirmations.reject(id, person, note),
                "agent.confirmation.rejected");
    }

    @PostMapping("/{id}/report")
    public String report(@PathVariable("id") String id, @RequestParam(value = "note", required = false) String note,
                         Authentication authentication, HttpServletRequest request,
                         RedirectAttributes redirectAttributes) {
        String person = person(authentication, request);
        return decide(id, redirectAttributes, () -> confirmations.report(id, person, note),
                "agent.confirmation.reported");
    }

    private String decide(String id, RedirectAttributes redirectAttributes, Runnable decision, String doneKey) {
        try {
            decision.run();
            redirectAttributes.addFlashAttribute("message", message(doneKey));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        } catch (IllegalStateException e) {
            redirectAttributes.addFlashAttribute("errorMessage", message("agent.confirmation.already.decided"));
        }
        return PAGE + id;
    }

    /**
     * The person deciding: the signed-in account, never an agent. A delegated agent holds a token of the person, so a
     * request the bridge stamped as an agent's is refused.
     */
    private static String person(Authentication authentication, HttpServletRequest request) {
        if (authentication == null || !StringUtils.hasText(authentication.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        if (request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                && StringUtils.hasText(stamp.agentId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An agent cannot confirm a request");
        }
        return authentication.getName();
    }

    /** The delegation the request named, else the person's delegation to the agent at the time it was asked. */
    private Optional<AgentDelegation> delegation(AgentConfirmation confirmation) {
        if (delegations == null || !"DELEGATED_AGENT".equals(confirmation.subjectKind())) {
            return Optional.empty();
        }
        try {
            return AgentDelegations.forRequest(delegations, confirmation.tenantId(), confirmation.userId(),
                    confirmation.agentId(), confirmation.delegationId(), confirmation.createdAt());
        } catch (RuntimeException e) {
            log.error("Reading the delegation of a confirmation failed: confirmationId={}",
                    confirmation.confirmationId(), e);
            return Optional.empty();
        }
    }

    /** The latest decision record of the agent for this person before the confirmation was asked, or null. */
    @Nullable
    private AuditLog decisionRecord(AgentConfirmation confirmation) {
        if (decisionRecords == null) {
            return null;
        }
        LocalDateTime asked = LocalDateTime.ofInstant(confirmation.createdAt(), ZoneId.systemDefault());
        boolean delegated = "DELEGATED_AGENT".equals(confirmation.subjectKind());
        try {
            return decisionRecords.findTop10ByAgentIdAndEventCategoryOrderByTimestampDesc(confirmation.agentId(),
                            "SECURITY_DECISION").stream()
                    .filter(row -> !delegated || confirmation.userId().equals(row.getDelegatorId()))
                    .filter(row -> row.getTimestamp() == null || !row.getTimestamp().isAfter(asked))
                    .findFirst().orElse(null);
        } catch (RuntimeException e) {
            log.error("Reading the decision record of a confirmation failed: confirmationId={}",
                    confirmation.confirmationId(), e);
            return null;
        }
    }

    private String message(String key) {
        return messageSource.getMessage(key, null, key, LocaleContextHolder.getLocale());
    }
}
