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
package io.contexa.contexacore.autonomous.agent;

import java.util.Locale;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The confirmation of an agent's request by the person accountable for it (docs/agent A5-2, A5-9, F-2). An agent
 * cannot answer the factors made for people, so a request a decision challenges (or one under an ended delegation,
 * or one a policy lets through only once confirmed) waits for that person: the person the agent acts for, or the
 * sponsor of an agent acting on its own. The person is told through the agent notices (mail by default), approves,
 * refuses or reports the request on the confirmation page, and the agent polls the confirmation and sends the request
 * again once approved. The approval is recorded as a verifiable authorization ({@link AgentConfirmationAuthorizer}),
 * is bound to that one request ({@link AgentRequestBinding}) and is used once. A confirmation not decided in time is
 * a refusal; a report stops the agent at once ({@link AgentContainmentService}). Every step is audited.
 */
@Slf4j
public class AgentConfirmationService {

    /** Where the confirmation page is, under the application's context path. */
    public static final String PAGE_PATH = "/contexa/agent-confirmations/";
    /** Where the agent polls its confirmation, under the application's context path. */
    public static final String STATUS_PATH = "/contexa/api/agent-confirmations/";
    static final int SWEEP_BATCH = 500;

    private final AgentConfirmationStore store;
    private final AgentConfirmationAuthorizer authorizer;
    private final AgentNotices notices;
    private final AgentRegistry registry;
    private final CentralAuditFacade audit;
    private final Duration timeout;
    private final Clock clock;
    private AgentContainmentService containment;

    public AgentConfirmationService(AgentConfirmationStore store, AgentConfirmationAuthorizer authorizer,
                                    @Nullable AgentNotices notices, @Nullable AgentRegistry registry,
                                    @Nullable CentralAuditFacade audit, Duration timeout, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer");
        this.notices = notices;
        this.registry = registry;
        this.audit = audit;
        this.timeout = timeout != null && !timeout.isNegative() && !timeout.isZero() ? timeout
                : Duration.ofMinutes(15);
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** What stops the agent when the person reports a request (A5-3). */
    public void setContainment(@Nullable AgentContainmentService containment) {
        this.containment = containment;
    }

    /**
     * Where a confirmation link starts: the configured address, else the application's path only. The address of the
     * agent's own request is never used, since the agent chooses its host header and the link goes to a person.
     *
     * @param configured  the configured address ({@code confirmation-link-base-url}), or null
     * @param contextPath the application's context path
     */
    public static String linkBase(@Nullable String configured, @Nullable String contextPath) {
        String base = StringUtils.hasText(configured) ? configured.trim().replaceAll("/+$", "") : "";
        return base + (contextPath != null ? contextPath : "");
    }

    /** How long a confirmation waits, and how long an approval may be used. */
    public Duration timeout() {
        return timeout;
    }

    /** What the request of an agent asks of the person, as the gate states it. */
    public record ConfirmationRequest(ZeroTrustSubject subject, String requestHash, String method, String target,
                                      String trigger, @Nullable String reason, @Nullable String correlationId,
                                      @Nullable String linkBase) {
    }

    /**
     * Asks the accountable person to confirm the request, or answers the confirmation already waiting for it.
     *
     * @return empty when no person is accountable for the agent (an agent on its own without a sponsor), or when a
     *         confirmation cannot keep the agent's identifiers whole ({@link AgentConfirmation#keeps})
     */
    public Optional<AgentConfirmation> request(ConfirmationRequest request) {
        ZeroTrustSubject subject = request.subject();
        if (subject == null || subject.agentId() == null || !StringUtils.hasText(request.requestHash())) {
            return Optional.empty();
        }
        if (!AgentConfirmation.keeps(subject)) {
            record(AuditEventCategory.AGENT_CONFIRMATION_REQUESTED, "contexa", null, subject, "UNKEEPABLE",
                    "The agent's identifiers are longer than a confirmation keeps; the request is refused",
                    Map.of("target", truncate(request.method() + " " + request.target(), 2048),
                            "trigger", request.trigger()));
            return Optional.empty();
        }
        String subjectKey = subject.storageKey();
        Instant now = now();
        Optional<AgentConfirmation> waiting = store.latest(subjectKey, request.requestHash(),
                AgentConfirmation.Status.PENDING).filter(pending -> pending.expiresAt().isAfter(now));
        if (waiting.isPresent()) {
            return waiting;
        }
        String recipient = recipient(subject);
        if (recipient == null) {
            record(AuditEventCategory.AGENT_CONFIRMATION_REQUESTED, "contexa", null, subject, "NO_ACCOUNTABLE_PERSON",
                    "No person is accountable for the agent; the request is refused",
                    Map.of("target", request.method() + " " + request.target(), "trigger", request.trigger()));
            return Optional.empty();
        }
        AgentConfirmation confirmation = store.save(new AgentConfirmation(UUID.randomUUID().toString(),
                subject.tenantId(), subject.kind().name(), subject.userId(), subject.agentId(),
                subject.delegationId(), recipient, request.requestHash(), request.method(),
                request.target(), request.trigger(), request.reason(), request.correlationId(),
                AgentConfirmation.Status.PENDING, now, now.plus(timeout), null, null, null, null, null));
        notify(confirmation, AgentNotice.CONFIRMATION_REQUESTED,
                "The agent " + confirmation.agentId() + " asks you to confirm a request",
                "The agent " + confirmation.agentId() + " is waiting for your confirmation before it runs "
                        + asked(confirmation) + reasonText(confirmation)
                        + ". Approve, refuse or report it before " + confirmation.expiresAt()
                        + "; without an answer it is refused." + agentWords(confirmation),
                link(request.linkBase(), PAGE_PATH + confirmation.confirmationId()));
        record(AuditEventCategory.AGENT_CONFIRMATION_REQUESTED, "contexa", confirmation, subject, "PENDING",
                confirmation.reason(), Map.of("target", confirmation.method() + " " + confirmation.target(),
                        "trigger", confirmation.trigger(), "recipient", recipient));
        return Optional.of(confirmation);
    }

    /** The confirmation as it stands now: one whose time ran out is expired first. */
    public Optional<AgentConfirmation> status(String confirmationId) {
        return store.find(confirmationId).map(this::expireIfOverdue);
    }

    /** The person's confirmations, latest first, each as it stands now. */
    public List<AgentConfirmation> forRecipient(String recipientId, int limit) {
        return store.forRecipient(recipientId, limit).stream().map(this::expireIfOverdue).toList();
    }

    /**
     * The person approves the request: the approval is recorded as an authorization and may be used by that request
     * once, until the timeout passes again.
     *
     * @throws IllegalArgumentException when the confirmation is unknown or not the person's to decide
     * @throws IllegalStateException    when it was decided already or its time ran out
     */
    public AgentConfirmation approve(String confirmationId, String personId, @Nullable String note) {
        AgentConfirmation pending = decidable(confirmationId, personId);
        Instant at = now();
        AgentConfirmation decided = pending.decided(AgentConfirmation.Status.APPROVED, at, personId, text(note), null,
                at.plus(timeout));
        String authorization = authorizer.authorize(decided);
        AgentConfirmation approved = decided.decided(AgentConfirmation.Status.APPROVED, at, personId, text(note),
                authorization, at.plus(timeout));
        if (!store.transition(approved, AgentConfirmation.Status.PENDING)) {
            throw new IllegalStateException("The confirmation was decided already");
        }
        record(AuditEventCategory.AGENT_CONFIRMATION_APPROVED, personId, approved, null, "APPROVED", text(note),
                Map.of("authorizationId", authorization, "target", approved.method() + " " + approved.target()));
        return approved;
    }

    /** The person refuses the request; the refusal is recorded. */
    public AgentConfirmation reject(String confirmationId, String personId, @Nullable String note) {
        AgentConfirmation pending = decidable(confirmationId, personId);
        Instant at = now();
        AgentConfirmation rejected = pending.decided(AgentConfirmation.Status.REJECTED, at, personId, text(note), null,
                pending.expiresAt());
        if (!store.transition(rejected, AgentConfirmation.Status.PENDING)) {
            throw new IllegalStateException("The confirmation was decided already");
        }
        record(AuditEventCategory.AGENT_CONFIRMATION_REJECTED, personId, rejected, null, "REJECTED", text(note),
                Map.of("target", rejected.method() + " " + rejected.target()));
        return rejected;
    }

    /**
     * The person reports the request: it is refused and the agent is stopped at once (AG-11k, A5-3), its delegation
     * revoked or, on its own, its registration suspended.
     */
    public AgentConfirmation report(String confirmationId, String personId, @Nullable String note) {
        AgentConfirmation pending = decidable(confirmationId, personId);
        Instant at = now();
        AgentConfirmation reported = pending.decided(AgentConfirmation.Status.REPORTED, at, personId, text(note), null,
                pending.expiresAt());
        if (!store.transition(reported, AgentConfirmation.Status.PENDING)) {
            throw new IllegalStateException("The confirmation was decided already");
        }
        List<String> steps = containment != null
                ? containment.onReport(subjectOf(reported), personId, text(note), reported.correlationId())
                : List.of();
        record(AuditEventCategory.AGENT_CONFIRMATION_REPORTED, personId, reported, null, "REPORTED", text(note),
                Map.of("target", reported.method() + " " + reported.target(), "steps", String.join(", ", steps)));
        return reported;
    }

    /**
     * The approval of this request, used: the request the approval is bound to runs once (A5-9). Empty when there is
     * no approval of this request in time, when its authorization does not verify, or when it was used already.
     *
     * @param confirmationId the confirmation the agent names, or null to look the request's approval up
     */
    public Optional<AgentConfirmation> consume(ZeroTrustSubject subject, String requestHash,
                                               @Nullable String confirmationId) {
        if (subject == null || subject.agentId() == null || !StringUtils.hasText(requestHash)) {
            return Optional.empty();
        }
        String subjectKey = subject.storageKey();
        Optional<AgentConfirmation> approval = StringUtils.hasText(confirmationId)
                ? store.find(confirmationId.trim()).filter(found -> found.subjectKey().equals(subjectKey))
                : store.latest(subjectKey, requestHash, AgentConfirmation.Status.APPROVED);
        if (approval.isEmpty() || approval.get().status() != AgentConfirmation.Status.APPROVED) {
            return Optional.empty();
        }
        AgentConfirmation approved = expireIfOverdue(approval.get());
        if (approved.status() != AgentConfirmation.Status.APPROVED) {
            return Optional.empty();
        }
        if (!approved.requestHash().equals(requestHash)) {
            record(AuditEventCategory.AGENT_CONFIRMATION_REFUSED, "contexa", approved, null, "OTHER_REQUEST",
                    "The approval was offered for another request than the one it was given for",
                    Map.of("target", approved.method() + " " + approved.target()));
            return Optional.empty();
        }
        if (!authorizer.verify(approved)) {
            record(AuditEventCategory.AGENT_CONFIRMATION_REFUSED, "contexa", approved, null, "UNVERIFIED",
                    "The approval's authorization does not verify",
                    Map.of("authorizationId", Objects.toString(approved.authorizationId(), "")));
            return Optional.empty();
        }
        Instant at = now();
        if (!store.markUsed(approved.confirmationId(), requestHash, at)) {
            return Optional.empty();
        }
        AgentConfirmation used = approved.withStatus(AgentConfirmation.Status.USED, at);
        try {
            authorizer.consumed(used);
        } catch (RuntimeException e) {
            log.error("The approval's authorization could not be marked spent: confirmationId={}",
                    used.confirmationId(), e);
        }
        record(AuditEventCategory.AGENT_CONFIRMATION_USED, "contexa", used, null, "USED", null,
                Map.of("authorizationId", Objects.toString(used.authorizationId(), ""),
                        "target", used.method() + " " + used.target()));
        return Optional.of(used);
    }

    /**
     * docs/agent F-2: a request of an agent under a delegation the person, or Contexa's stop, revoked is refused
     * without asking anyone again; the refusal is recorded.
     */
    public void recordRevokedDelegation(ZeroTrustSubject subject, AgentDelegation revoked, String method,
                                        String target) {
        recordEndedDelegation(subject, revoked, method, target, "REFUSED");
    }

    /**
     * docs/agent F-2, G-9: a request of an agent under an ended delegation, in the report-only mode: what would have
     * been done ({@code OBSERVED}) is recorded and the request goes on.
     */
    public void recordEndedDelegation(ZeroTrustSubject subject, AgentDelegation ended, String method, String target,
                                      String outcome) {
        record(AuditEventCategory.AGENT_DELEGATION_ENDED, "contexa", null, subject, outcome,
                ended.revokedAt() != null && !ended.revokedAt().isAfter(ended.expiresAt())
                        ? "The delegation " + ended.delegationId() + " was revoked at " + ended.revokedAt()
                        + (StringUtils.hasText(ended.revokedBy()) ? " by " + ended.revokedBy() : "")
                        : "The delegation " + ended.delegationId() + " ended at " + ended.end(),
                Map.of("target", truncate(method + " " + target, 2048), "delegationId", ended.delegationId()));
    }

    /**
     * Expires the confirmations whose time ran out: a request not decided in time is refused and the person is told;
     * an approval not used in time can no longer be used.
     *
     * @return how many were expired
     */
    public int expireOverdue() {
        int expired = 0;
        for (AgentConfirmation overdue : store.overdue(now(), SWEEP_BATCH)) {
            if (expireIfOverdue(overdue).status() == AgentConfirmation.Status.EXPIRED) {
                expired++;
            }
        }
        return expired;
    }

    private AgentConfirmation expireIfOverdue(AgentConfirmation confirmation) {
        if ((confirmation.status() != AgentConfirmation.Status.PENDING
                && confirmation.status() != AgentConfirmation.Status.APPROVED)
                || confirmation.expiresAt().isAfter(now())) {
            return confirmation;
        }
        AgentConfirmation expired = confirmation.withStatus(AgentConfirmation.Status.EXPIRED, null);
        if (!store.transition(expired, confirmation.status())) {
            return store.find(confirmation.confirmationId()).orElse(confirmation);
        }
        boolean undecided = confirmation.status() == AgentConfirmation.Status.PENDING;
        record(AuditEventCategory.AGENT_CONFIRMATION_EXPIRED, "contexa", expired, null, "EXPIRED",
                undecided ? "Not confirmed in time: the request is refused"
                        : "The approval was not used in time",
                Map.of("target", expired.method() + " " + expired.target(), "was", confirmation.status().name()));
        if (undecided) {
            notify(expired, AgentNotice.CONFIRMATION_EXPIRED,
                    "A request of the agent " + expired.agentId() + " was refused without your answer",
                    "The agent " + expired.agentId() + " waited for your confirmation of " + asked(expired)
                            + " until " + expired.expiresAt() + ". It was not confirmed in time, "
                            + "so the request was refused.", null);
        }
        return expired;
    }

    private AgentConfirmation decidable(String confirmationId, String personId) {
        if (!StringUtils.hasText(confirmationId) || !StringUtils.hasText(personId)) {
            throw new IllegalArgumentException("A confirmation and a person are required");
        }
        AgentConfirmation confirmation = store.find(confirmationId.trim())
                .orElseThrow(() -> new IllegalArgumentException("Unknown confirmation: " + confirmationId));
        if (!confirmation.recipientId().equals(personId.trim())) {
            throw new IllegalArgumentException("The confirmation is not this person's to decide");
        }
        AgentConfirmation current = expireIfOverdue(confirmation);
        if (current.status() != AgentConfirmation.Status.PENDING) {
            throw new IllegalStateException("The confirmation is " + current.status().name().toLowerCase(Locale.ROOT)
                    + " already");
        }
        return current;
    }

    /** The person accountable for the subject's request: the delegator, else the agent's sponsor. */
    @Nullable
    private String recipient(ZeroTrustSubject subject) {
        if (subject.delegatedAgent()) {
            return subject.userId();
        }
        if (registry == null) {
            return null;
        }
        try {
            return AgentRegistrations.find(registry, subject.tenantId(), subject.agentId())
                    .map(AgentRegistration::sponsorId).filter(StringUtils::hasText).orElse(null);
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed: agentId={}", subject.agentId(), e);
            return null;
        }
    }

    private static ZeroTrustSubject subjectOf(AgentConfirmation confirmation) {
        return new ZeroTrustSubject(confirmation.tenantId(), confirmation.userId(),
                SubjectKind.valueOf(confirmation.subjectKind()),
                confirmation.agentId(), confirmation.delegationId());
    }

    private void notify(AgentConfirmation confirmation, String kind, String subject, String message,
                        @Nullable String link) {
        if (notices == null) {
            return;
        }
        try {
            notices.notify(kind, confirmation.tenantId(), confirmation.recipientId(), confirmation.agentId(),
                    confirmation.delegationId(), subject, message, link, confirmation.confirmationId());
        } catch (RuntimeException e) {
            log.error("Agent confirmation notice failed: confirmationId={}", confirmation.confirmationId(), e);
        }
    }

    private void record(AuditEventCategory category, String principal, @Nullable AgentConfirmation confirmation,
                        @Nullable ZeroTrustSubject subject, String outcome, @Nullable String reason,
                        Map<String, String> details) {
        if (audit == null) {
            return;
        }
        Map<String, Object> all = new LinkedHashMap<>(details);
        String agentId = confirmation != null ? confirmation.agentId() : subject != null ? subject.agentId() : null;
        String kind = confirmation != null ? confirmation.subjectKind()
                : subject != null ? subject.kind().name() : null;
        boolean delegated = "DELEGATED_AGENT".equals(kind);
        if (confirmation != null) {
            all.put("confirmationId", confirmation.confirmationId());
        }
        try {
            audit.recordSync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(principal)
                    .resourceIdentifier(confirmation != null ? truncate(confirmation.target(), 512)
                            : subject != null ? subject.agentId() : null)
                    .requestUri(confirmation != null ? confirmation.target() : null)
                    .eventSource("CORE")
                    .action(category.name())
                    .decision(outcome)
                    .outcome(outcome)
                    .reason(reason)
                    .subjectKind(kind)
                    .agentId(agentId)
                    .delegatorId(delegated ? (confirmation != null ? confirmation.userId() : subject.userId()) : null)
                    .delegationId(confirmation != null ? confirmation.delegationId()
                            : subject != null ? subject.delegationId() : null)
                    .tenantId(confirmation != null ? confirmation.tenantId()
                            : subject != null ? subject.tenantId() : null)
                    .correlationId(confirmation != null ? truncate(confirmation.correlationId(), 64) : null)
                    .details(all)
                    .build());
        } catch (RuntimeException e) {
            log.error("Agent confirmation audit failed: category={}", category, e);
        }
    }

    private Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.MICROS);
    }

    private static String link(@Nullable String base, String path) {
        return StringUtils.hasText(base) ? base.replaceAll("/+$", "") + path : path;
    }

    /**
     * The request as the person is told it: what the agent sent and, when the application serves another path than the
     * one it spells, that path ({@link AgentConfirmation#routedPath}).
     */
    private static String asked(AgentConfirmation confirmation) {
        String routed = confirmation.routedPath();
        return confirmation.method() + " " + confirmation.target()
                + (routed != null ? " (the application serves this as " + routed + ")" : "");
    }

    /** The reason of a decision or of an ended delegation: Contexa's own, said in Contexa's sentence. */
    private static String reasonText(AgentConfirmation confirmation) {
        return StringUtils.hasText(confirmation.reason()) && !agentWrote(confirmation)
                ? " (" + confirmation.reason() + ")" : "";
    }

    /** What the agent wrote when it asked: said after Contexa's words and as the agent's, as the page shows it. */
    private static String agentWords(AgentConfirmation confirmation) {
        return StringUtils.hasText(confirmation.reason()) && agentWrote(confirmation)
                ? " Written by the agent, not checked by Contexa: " + confirmation.reason() : "";
    }

    private static boolean agentWrote(AgentConfirmation confirmation) {
        return AgentConfirmation.REQUESTED.equals(confirmation.trigger());
    }

    @Nullable
    private static String text(@Nullable String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    @Nullable
    private static String truncate(@Nullable String value, int length) {
        return value != null && value.length() > length ? value.substring(0, length) : value;
    }
}
