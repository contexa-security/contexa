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
package io.contexa.contexaidentity.security.zerotrust;

import java.util.Locale;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.AgentConfirmationFacts;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacore.autonomous.agent.AgentCallGuard;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegations;
import io.contexa.contexacore.autonomous.agent.AgentRequestBinding;
import io.contexa.contexacore.autonomous.agent.AgentScopeRestriction;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.security.zerotrust.ConfirmedAgentAuthentication;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;

/**
 * Where an agent's request meets the confirmation of the person accountable for it (docs/agent A5-2, A5-9, F-2). A
 * request asks for a confirmation when the decision in force for the agent is a CHALLENGE, or when the person's
 * delegation to the agent has expired or not started (F-2); a request under a revoked delegation is refused. The
 * agent answers {@code 403 AGENT_CONFIRMATION_REQUIRED} with the confirmation's identifier and where to poll it, and
 * sends the same request again once approved: the approval bound to that request is used then, once, and the
 * request runs with the agent's own authorities. An agent may name its confirmation in the
 * {@value #CONFIRMATION_HEADER} header, which also lets a policy that requires a confirmation see it.
 */
@Slf4j
public class AgentConfirmationGate {

    /** The header an agent may name its approved confirmation in. */
    public static final String CONFIRMATION_HEADER = "Contexa-Agent-Confirmation";
    /** The answer to a request under a revoked delegation. */
    public static final String DELEGATION_REVOKED = "DELEGATION_REVOKED";
    /** The answer to a request too large to bind a confirmation to. */
    public static final String CONFIRMATION_UNBINDABLE = "AGENT_CONFIRMATION_UNBINDABLE";
    /** The answer to a request outside the agent's narrowed scope (A5-4). */
    public static final String SCOPE_NARROWED = "AGENT_SCOPE_NARROWED";
    /** The answer to a request past the agent's call limit (A5-7). */
    public static final String CALL_LIMIT = AgentCallGuard.CALL_LIMIT;
    /** The request's binding, kept for a CHALLENGE decided in the request (A5-2). */
    private static final String BOUND_REQUEST = AgentConfirmationGate.class.getName() + ".boundRequest";
    /** Set when a CHALLENGE decided in the request asked for the request's confirmation. */
    private static final String ASKED_IN_REQUEST = AgentConfirmationGate.class.getName() + ".askedInRequest";

    private final AgentConfirmationService confirmations;
    private final ZeroTrustActionRepository actions;
    private final AuthResponseWriter responseWriter;
    private final int maxBodyBytes;
    private final String linkBaseUrl;
    private final Clock clock;
    private DelegationRegistry delegations;
    private AgentScopeService scopes;
    private AgentCallGuard callGuard;
    private BooleanSupplier enforcing = () -> true;

    public AgentConfirmationGate(AgentConfirmationService confirmations, ZeroTrustActionRepository actions,
                                 AuthResponseWriter responseWriter, int maxBodyBytes, @Nullable String linkBaseUrl,
                                 @Nullable Clock clock) {
        this.confirmations = Objects.requireNonNull(confirmations, "confirmations");
        this.actions = actions;
        this.responseWriter = Objects.requireNonNull(responseWriter, "responseWriter");
        this.maxBodyBytes = maxBodyBytes > 0 ? maxBodyBytes : 1024 * 1024;
        this.linkBaseUrl = StringUtils.hasText(linkBaseUrl) ? linkBaseUrl.trim() : null;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** docs/agent F-2: where the person's delegations to agents are read; without it, ended delegations are not met. */
    public void setDelegationRegistry(@Nullable DelegationRegistry delegations) {
        this.delegations = delegations;
    }

    /**
     * docs/agent A5-4: the narrowed scopes; a request outside the one in force is refused unless its accountable
     * person confirmed that very request.
     */
    public void setScopes(@Nullable AgentScopeService scopes) {
        this.scopes = scopes;
    }

    /**
     * docs/agent G-9: whether the gate's own checks are enforced. In the report-only mode (SHADOW) an ended
     * delegation and a narrowed scope are recorded and the request goes on; a CHALLENGE in force still waits for its
     * confirmation, as a person's does for the step-up.
     */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    /** docs/agent A5-7: the call limits and the denial alarm of agents. */
    public void setCallGuard(@Nullable AgentCallGuard callGuard) {
        this.callGuard = callGuard;
    }

    /**
     * Lets the agent's request on, or answers it. Its answer counts toward the agent's denial alarm (A5-7): a refusal
     * here or further on counts, a request waiting for its confirmation does not.
     *
     * @return whether the request went on
     */
    public boolean filter(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                          ZeroTrustSubject subject, ZeroTrustAction action) throws IOException, ServletException {
        if (callGuard != null) {
            AgentCallGuard.Admission admission = callGuard.admit(subject, null);
            if (!admission.admitted()) {
                response.setHeader("Retry-After", String.valueOf(admission.retryAfterSeconds()));
                writeRefusal(response, request, CALL_LIMIT, "The agent passed its call limit; slow down",
                        Map.of("scope", admission.scope(), "limit", admission.limit(),
                                "retryAfterSeconds", admission.retryAfterSeconds()));
                callGuard.outcome(subject, true);
                return false;
            }
            request.setAttribute(BridgeRequestAttributes.AGENT_RECENT_CALLS, admission.calls());
        }
        Outcome outcome = decide(request, response, chain, subject, action);
        if (callGuard != null && outcome != Outcome.WAITS) {
            int status = response.getStatus();
            callGuard.outcome(subject, outcome == Outcome.REFUSED || status == HttpServletResponse.SC_UNAUTHORIZED
                    || status == HttpServletResponse.SC_FORBIDDEN);
        }
        return outcome == Outcome.WENT;
    }

    /** How the gate answered a request. */
    private enum Outcome {
        WENT,
        WAITS,
        REFUSED
    }

    private Outcome decide(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                           ZeroTrustSubject subject, ZeroTrustAction action) throws IOException, ServletException {
        String named = request.getHeader(CONFIRMATION_HEADER);
        Instant at = requestTime(request);
        Optional<AgentDelegation> ended = endedDelegation(subject, at);
        if (ended.isPresent() && !enforcing.getAsBoolean()) {
            confirmations.recordEndedDelegation(subject, ended.get(), request.getMethod(), target(request),
                    "OBSERVED");
            ended = Optional.empty();
        }
        if (ended.isPresent() && ended.get().revokedAt() != null && !ended.get().revokedAt()
                .isAfter(ended.get().expiresAt())) {
            confirmations.recordRevokedDelegation(subject, ended.get(), request.getMethod(), target(request));
            writeRefusal(response, request, DELEGATION_REVOKED,
                    "The delegation to this agent was revoked; the person delegates again for it to act",
                    Map.of("delegationId", ended.get().delegationId()));
            return Outcome.REFUSED;
        }
        String trigger = action == ZeroTrustAction.CHALLENGE ? AgentConfirmation.DECISION_CHALLENGE
                : ended.isPresent() ? AgentConfirmation.DELEGATION_ENDED : null;
        // Every request is bound, so a CHALLENGE decided in the request can ask for that very request too.
        Bound bound = bind(request, subject);
        if (trigger == null && !StringUtils.hasText(named)) {
            if (refusedByScope(request, response, subject)) {
                return Outcome.REFUSED;
            }
            return goOn(bound, response, chain);
        }
        if (bound.hash() == null) {
            if (trigger == null) {
                if (refusedByScope(request, response, subject)) {
                    return Outcome.REFUSED;
                }
                return goOn(bound, response, chain);
            }
            writeRefusal(response, request, CONFIRMATION_UNBINDABLE,
                    "The request is too large to be confirmed; send it in smaller parts", Map.of());
            return Outcome.REFUSED;
        }
        Optional<AgentConfirmation> used = confirmations.consume(subject, bound.hash(), named);
        if (used.isPresent()) {
            AgentConfirmation confirmation = used.get();
            bound.request().setAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION, confirmation.confirmationId());
            // docs/agent F-5: what the person confirmed travels with the request into its decision context.
            AgentConfirmationFacts.keep(bound.request(), AgentConfirmationFacts.of(confirmation.confirmationId(),
                    confirmation.decidedBy(), confirmation.decidedAt(), confirmation.createdAt(),
                    confirmation.trigger(), confirmation.authorizationId(), confirmation.usedAt()));
            if (action == ZeroTrustAction.CHALLENGE) {
                ConfirmedAgentAuthentication.restore(bound.request(), SecurityContextHolder.getContext());
            }
            return goOn(bound, response, chain);
        }
        if (trigger == null) {
            if (refusedByScope(request, response, subject)) {
                return Outcome.REFUSED;
            }
            return goOn(bound, response, chain);
        }
        Optional<AgentConfirmation> asked = confirmations.request(new AgentConfirmationService.ConfirmationRequest(
                subject, bound.hash(), request.getMethod(), target(request), trigger,
                reason(subject, trigger, ended.orElse(null), at), correlationId(request), linkBase(request)));
        writeConfirmationRequired(response, request, asked.orElse(null), trigger);
        return asked.isPresent() ? Outcome.WAITS : Outcome.REFUSED;
    }

    /**
     * docs/agent A5-2: answers an agent's request a CHALLENGE decided in the request itself stopped (a synchronous
     * operation, or an agent's request decided in place, F-1): its accountable person is asked to confirm that very
     * request, as for a CHALLENGE in force, and the agent gets the same answer. A request the gate could not bind
     * (a body over the bound size) is left to the plain CHALLENGE answer.
     *
     * @return whether the answer was written
     */
    public boolean answerDecidedChallenge(HttpServletRequest request, HttpServletResponse response,
                                          @Nullable ZeroTrustSubject subject) throws IOException {
        if (subject == null || subject.agentId() == null
                || !(request.getAttribute(BOUND_REQUEST) instanceof String hash)) {
            return false;
        }
        String trigger = AgentConfirmation.DECISION_CHALLENGE;
        Optional<AgentConfirmation> asked = confirmations.request(new AgentConfirmationService.ConfirmationRequest(
                subject, hash, request.getMethod(), target(request), trigger,
                reason(subject, trigger, null, clock.instant()), correlationId(request), linkBase(request)));
        writeConfirmationRequired(response, request, asked.orElse(null), trigger);
        request.setAttribute(ASKED_IN_REQUEST, asked.isPresent());
        return true;
    }

    /** Lets the bound request on; when a CHALLENGE decided in it asked for its confirmation, the request waits. */
    private Outcome goOn(Bound bound, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (bound.hash() != null) {
            bound.request().setAttribute(BOUND_REQUEST, bound.hash());
        }
        chain.doFilter(bound.request(), response);
        return Boolean.TRUE.equals(bound.request().getAttribute(ASKED_IN_REQUEST)) ? Outcome.WAITS : Outcome.WENT;
    }

    /** docs/agent A5-4: answers a request outside the agent's narrowed scope; whether it did. */
    private boolean refusedByScope(HttpServletRequest request, HttpServletResponse response, ZeroTrustSubject subject)
            throws IOException {
        if (scopes == null) {
            return false;
        }
        Optional<AgentScopeRestriction> refusing;
        try {
            refusing = scopes.refusing(subject, request.getMethod(), path(request));
        } catch (RuntimeException e) {
            log.error("Reading the agent's narrowed scope failed: agentId={}", subject.agentId(), e);
            return false;
        }
        if (refusing.isEmpty()) {
            return false;
        }
        if (!enforcing.getAsBoolean()) {
            log.info("[AgentConfirmationGate][SHADOW] A request outside the agent's narrowed scope goes on: "
                    + "agentId={}, allowed={}", subject.agentId(), refusing.get().allowed());
            return false;
        }
        writeRefusal(response, request, SCOPE_NARROWED,
                "A decision narrowed this agent's requests; this operation waits until the narrowing ends or the "
                        + "accountable person confirms the request",
                Map.of("allowed", refusing.get().allowed().stream().map(Enum::name).sorted().toList(),
                        "until", refusing.get().until().toString(),
                        "operation", AgentScopeService.operation(request.getMethod(), path(request)).name()));
        return true;
    }

    /**
     * The person's delegation to the agent that has ended, or empty: not in force at the request's time (expired or
     * not started), or revoked by now. A revocation stops the agent from when it was made, whatever time the
     * request is recorded at.
     */
    private Optional<AgentDelegation> endedDelegation(ZeroTrustSubject subject, Instant at) {
        if (delegations == null || !subject.delegatedAgent()) {
            return Optional.empty();
        }
        try {
            Instant now = clock.instant();
            return AgentDelegations.forRequest(delegations, subject.tenantId(), subject.userId(), subject.agentId(),
                    subject.delegationId(), at).filter(delegation -> !delegation.validAt(at)
                    || delegation.revokedAt() != null && !delegation.revokedAt().isAfter(now));
        } catch (RuntimeException e) {
            log.error("Delegation lookup failed for an agent's request: agentId={}", subject.agentId(), e);
            return Optional.empty();
        }
    }

    /** The request with its body kept, and its binding; no binding for a body over the bound size. */
    private Bound bind(HttpServletRequest request, ZeroTrustSubject subject) throws IOException {
        String path = path(request);
        if (formPost(request)) {
            return new Bound(request, AgentRequestBinding.hash(subject.tenantId(), subject.userId(),
                    subject.agentId(), request.getMethod(), path, null, null, request.getParameterMap()));
        }
        CachedBodyRequest cached = CachedBodyRequest.of(request, maxBodyBytes);
        if (!cached.bound()) {
            return new Bound(cached, null);
        }
        byte[] body = cached.body();
        return new Bound(cached, AgentRequestBinding.hash(subject.tenantId(), subject.userId(), subject.agentId(),
                request.getMethod(), path, request.getQueryString(),
                body.length > 0 ? AgentRequestBinding.sha256Hex(body) : null, null));
    }

    /**
     * The moment the delegation is read at: the time the host recorded for the request, as the decision reads the
     * delegation at it (the event's time, {@code RecordedDelegationContextProvider}), else now.
     */
    private Instant requestTime(HttpServletRequest request) {
        Instant observed = RequestInfoExtractor.extractObservedAt(request);
        return observed != null ? observed : clock.instant();
    }

    @Nullable
    private String reason(ZeroTrustSubject subject, String trigger, @Nullable AgentDelegation ended, Instant at) {
        if (AgentConfirmation.DELEGATION_ENDED.equals(trigger) && ended != null) {
            if (ended.validAt(at)) {
                return "The delegation " + ended.delegationId() + " was revoked at " + ended.revokedAt();
            }
            return ended.validFrom() != null && at.isBefore(ended.validFrom())
                    ? "The delegation " + ended.delegationId() + " starts only at " + ended.validFrom()
                    : "The delegation " + ended.delegationId() + " expired at " + ended.expiresAt();
        }
        if (actions == null) {
            return null;
        }
        try {
            ZeroTrustActionRepository.ZeroTrustAnalysisData analysis = actions.getAnalysisData(subject.storageKey());
            if (analysis == null) {
                return null;
            }
            return StringUtils.hasText(analysis.reasoningSummary()) ? analysis.reasoningSummary()
                    : analysis.reasoning();
        } catch (RuntimeException e) {
            log.error("Reading the decision's reasoning failed: agentId={}", subject.agentId(), e);
            return null;
        }
    }

    private void writeConfirmationRequired(HttpServletResponse response, HttpServletRequest request,
                                           @Nullable AgentConfirmation confirmation, String trigger)
            throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", ZeroTrustChallengeFilter.AGENT_CONFIRMATION_REQUIRED);
        body.put("trigger", trigger);
        if (confirmation == null) {
            body.put("message", "No person is accountable for this agent, so the request cannot be confirmed");
        } else {
            body.put("message", "The person accountable for this agent must confirm this request; poll the "
                    + "confirmation and send the same request again once it is approved");
            body.put("confirmationId", confirmation.confirmationId());
            body.put("status", confirmation.status().name());
            body.put("statusUrl", request.getContextPath() + AgentConfirmationService.STATUS_PATH
                    + confirmation.confirmationId());
            body.put("expiresAt", confirmation.expiresAt().toString());
            body.put("confirmationHeader", CONFIRMATION_HEADER);
        }
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_FORBIDDEN,
                ZeroTrustChallengeFilter.AGENT_CONFIRMATION_REQUIRED, (String) body.get("message"),
                request.getRequestURI(), body);
    }

    private void writeRefusal(HttpServletResponse response, HttpServletRequest request, String error, String message,
                              Map<String, Object> facts) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("message", message);
        body.putAll(facts);
        int status = switch (error) {
            case CONFIRMATION_UNBINDABLE -> HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE;
            case CALL_LIMIT -> 429;
            default -> HttpServletResponse.SC_FORBIDDEN;
        };
        responseWriter.writeErrorResponse(response, status, error, message, request.getRequestURI(), body);
    }

    /** Where the confirmation link starts ({@link AgentConfirmationService#linkBase}). */
    private String linkBase(HttpServletRequest request) {
        return AgentConfirmationService.linkBase(linkBaseUrl, request.getContextPath());
    }

    @Nullable
    private static String correlationId(HttpServletRequest request) {
        Object requestId = request.getAttribute("requestId");
        return requestId != null ? requestId.toString() : request.getHeader("X-Request-Id");
    }

    private static boolean formPost(HttpServletRequest request) {
        String type = request.getContentType();
        return type != null && type.toLowerCase(Locale.ROOT).startsWith(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
    }

    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        return StringUtils.hasText(context) && uri.startsWith(context) ? uri.substring(context.length()) : uri;
    }

    private static String target(HttpServletRequest request) {
        return path(request) + (StringUtils.hasText(request.getQueryString()) ? "?" + request.getQueryString() : "");
    }

    private record Bound(HttpServletRequest request, @Nullable String hash) {
    }
}
