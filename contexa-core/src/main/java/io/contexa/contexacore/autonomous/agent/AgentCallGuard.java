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

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;

/**
 * The call limits and the denial alarm of agents (docs/agent A5-7, AG-11e; OWASP ASI02, ASI08; MCP rate limiting).
 * Every request of an agent is counted for its delegation (one person's work, the agent's decision key) and for the
 * agent across everyone it acts for, over the last minute. Past a limit the request is slowed down, or the agent is
 * stopped as a BLOCK stops it; within the limits, and for people, nothing changes. An agent whose requests are refused
 * unusually often raises an alarm: audited, and its accountable person told. The counts are this instance's.
 */
@Slf4j
public class AgentCallGuard {

    /** What a request of an agent may do under the limits. */
    public record Admission(boolean admitted, @Nullable String scope, int calls, int limit, long retryAfterSeconds) {

        static final Admission IN_LIMITS = new Admission(true, null, 0, 0, 0);
    }

    static final Duration MINUTE = Duration.ofMinutes(1);
    static final int CAPACITY = 20_000;

    private final SecurityZeroTrustProperties.CallLimit limits;
    private final SecurityZeroTrustProperties.DenialAlarm alarm;
    private final AgentNotices notices;
    private final AgentRegistry registry;
    private final CentralAuditFacade audit;
    private final Clock clock;
    private final Map<String, Deque<Instant>> calls = new ConcurrentHashMap<>();
    private final Map<String, Deque<Outcome>> outcomes = new ConcurrentHashMap<>();
    private final Map<String, Instant> lastReported = new ConcurrentHashMap<>();
    private AgentContainmentService containment;
    private BooleanSupplier enforcing = () -> true;

    private record Outcome(Instant at, boolean denied) {
    }

    public AgentCallGuard(SecurityZeroTrustProperties.CallLimit limits, SecurityZeroTrustProperties.DenialAlarm alarm,
                          @Nullable AgentNotices notices, @Nullable AgentRegistry registry,
                          @Nullable CentralAuditFacade audit, @Nullable Clock clock) {
        this.limits = limits != null ? limits : new SecurityZeroTrustProperties.CallLimit();
        this.alarm = alarm != null ? alarm : new SecurityZeroTrustProperties.DenialAlarm();
        this.notices = notices;
        this.registry = registry;
        this.audit = audit;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * docs/agent G-9: whether limits are enforced; in the report-only mode (SHADOW) a passed limit is recorded as
     * {@code OBSERVED} and the request goes on.
     */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    /** What stops an agent past its limit when the limit stops ({@code on-exceed: STOP}). */
    public void setContainment(@Nullable AgentContainmentService containment) {
        this.containment = containment;
    }

    /**
     * Counts the agent's request and answers whether it is within the limits.
     *
     * @param clientId the agent's client as the request's credential names it, or null
     */
    public Admission admit(ZeroTrustSubject subject, @Nullable String clientId) {
        if (!limits.isEnabled() || subject == null || subject.agentId() == null) {
            return Admission.IN_LIMITS;
        }
        Instant now = clock.instant();
        int delegationCalls = count("delegation:" + subject.storageKey(), now);
        int agentCalls = count("agent:" + subject.agentId(), now);
        Admission admission;
        if (delegationCalls > limits.getPerDelegationPerMinute()) {
            admission = new Admission(false, "DELEGATION", delegationCalls, limits.getPerDelegationPerMinute(),
                    retryAfter("delegation:" + subject.storageKey(), limits.getPerDelegationPerMinute(), now));
        } else if (agentCalls > limits.getPerAgentPerMinute()) {
            admission = new Admission(false, "AGENT", agentCalls, limits.getPerAgentPerMinute(),
                    retryAfter("agent:" + subject.agentId(), limits.getPerAgentPerMinute(), now));
        } else {
            return new Admission(true, null, delegationCalls, limits.getPerDelegationPerMinute(), 0);
        }
        boolean enforced = enforcing.getAsBoolean();
        exceeded(subject, clientId, admission, now, enforced);
        return enforced ? admission
                : new Admission(true, admission.scope(), admission.calls(), admission.limit(), 0);
    }

    /** How many requests the subject's delegation made in the last minute (A1-9 policy condition). */
    public int recentCalls(ZeroTrustSubject subject) {
        if (subject == null || subject.agentId() == null) {
            return 0;
        }
        Deque<Instant> recent = calls.get("delegation:" + subject.storageKey());
        if (recent == null) {
            return 0;
        }
        Instant since = clock.instant().minus(MINUTE);
        synchronized (recent) {
            return (int) recent.stream().filter(at -> at.isAfter(since)).count();
        }
    }

    /** The answer the agent's request got: a refusal counts toward the denial alarm. */
    public void outcome(ZeroTrustSubject subject, boolean denied) {
        if (!alarm.isEnabled() || subject == null || subject.agentId() == null) {
            return;
        }
        Instant now = clock.instant();
        String key = subject.storageKey();
        if (outcomes.size() >= CAPACITY) {
            Instant old = now.minus(alarm.getWindow());
            outcomes.entrySet().removeIf(entry -> {
                synchronized (entry.getValue()) {
                    Outcome last = entry.getValue().peekLast();
                    return last == null || !last.at().isAfter(old);
                }
            });
        }
        Deque<Outcome> window = outcomes.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        int requests;
        int refused;
        synchronized (window) {
            window.addLast(new Outcome(now, denied));
            Instant since = now.minus(alarm.getWindow());
            while (!window.isEmpty() && !window.peekFirst().at().isAfter(since)) {
                window.pollFirst();
            }
            requests = window.size();
            refused = (int) window.stream().filter(Outcome::denied).count();
        }
        if (requests >= alarm.getMinRequests() && (double) refused / requests >= alarm.getRate()
                && reportDue("alarm:" + key, now, alarm.getWindow())) {
            raiseAlarm(subject, requests, refused);
        }
    }

    private int count(String key, Instant now) {
        trim();
        Deque<Instant> recent = calls.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        Instant since = now.minus(MINUTE);
        synchronized (recent) {
            while (!recent.isEmpty() && !recent.peekFirst().isAfter(since)) {
                recent.pollFirst();
            }
            recent.addLast(now);
            return recent.size();
        }
    }

    /**
     * The seconds until the next request is within {@code limit} again (docs/agent CF-26): every counted call, the
     * refused ones too, stays in the minute, so as many of the oldest must leave it as leave one place under the
     * limit for that request. Calls made while waiting are counted and make the next wait longer.
     */
    private long retryAfter(String key, int limit, Instant now) {
        Deque<Instant> recent = calls.get(key);
        if (recent == null) {
            return 1;
        }
        synchronized (recent) {
            int leaving = recent.size() - limit + 1;
            Instant last = null;
            Iterator<Instant> oldestFirst = recent.iterator();
            for (int left = 0; left < leaving && oldestFirst.hasNext(); left++) {
                last = oldestFirst.next();
            }
            return last == null ? 1 : Math.max(1, Duration.between(now, last.plus(MINUTE)).toSeconds() + 1);
        }
    }

    private void exceeded(ZeroTrustSubject subject, @Nullable String clientId, Admission admission, Instant now,
                          boolean enforced) {
        boolean stop = enforced && limits.getOnExceed() == SecurityZeroTrustProperties.CallLimit.OnExceed.STOP;
        if (!reportDue("limit:" + subject.storageKey(), now, MINUTE)) {
            return;
        }
        String why = "The agent made " + admission.calls() + " calls in a minute for its " + admission.scope()
                .toLowerCase(Locale.ROOT) + " (limit " + admission.limit() + ")";
        List<String> steps = List.of();
        if (stop && containment != null) {
            steps = containment.onBlock(subject, clientId, null, why, null);
        }
        record(AuditEventCategory.AGENT_CALL_LIMIT_EXCEEDED, subject, !enforced ? "OBSERVED"
                        : stop ? "STOPPED" : "THROTTLED", why,
                Map.of("scope", admission.scope(), "calls", String.valueOf(admission.calls()),
                        "limit", String.valueOf(admission.limit()), "steps", String.join(", ", steps)));
    }

    private void raiseAlarm(ZeroTrustSubject subject, int requests, int refused) {
        String why = refused + " of the agent's " + requests + " requests in " + alarm.getWindow().toMinutes()
                + " minutes were refused";
        log.warn("[AgentCallGuard] Denial rate alarm: agentId={}, subject={}, {}", subject.agentId(),
                subject.storageKey(), why);
        record(AuditEventCategory.AGENT_DENIAL_RATE_ALARM, subject, "ALARM", why,
                Map.of("requests", String.valueOf(requests), "refused", String.valueOf(refused)));
        String recipient = accountable(subject);
        if (notices != null && recipient != null) {
            try {
                notices.notify(AgentNotice.DENIAL_RATE_ALARM, subject.tenantId(), recipient, subject.agentId(),
                        subject.delegationId(), "The agent " + subject.agentId() + " is refused unusually often",
                        "Contexa refused " + why.toLowerCase(Locale.ROOT) + ". Check what the agent is doing; "
                                + "report it from your confirmations to stop it.", null, null);
            } catch (RuntimeException e) {
                log.error("Denial rate alarm notice failed: agentId={}", subject.agentId(), e);
            }
        }
    }

    @Nullable
    private String accountable(ZeroTrustSubject subject) {
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
            return null;
        }
    }

    private boolean reportDue(String key, Instant now, Duration every) {
        boolean[] due = new boolean[1];
        lastReported.compute(key, (ignored, last) -> {
            if (last == null || !last.plus(every).isAfter(now)) {
                due[0] = true;
                return now;
            }
            return last;
        });
        return due[0];
    }

    private void record(AuditEventCategory category, ZeroTrustSubject subject, String outcome, String reason,
                        Map<String, String> details) {
        if (audit == null) {
            return;
        }
        try {
            audit.recordSync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName("contexa")
                    .resourceIdentifier(subject.agentId())
                    .eventSource("CORE")
                    .action(category.name())
                    .decision(outcome)
                    .outcome(outcome)
                    .reason(reason)
                    .subjectKind(subject.kind().name())
                    .agentId(subject.agentId())
                    .delegatorId(subject.delegatedAgent() ? subject.userId() : null)
                    .delegationId(subject.delegationId())
                    .tenantId(subject.tenantId())
                    .details(new LinkedHashMap<String, Object>(details))
                    .build());
        } catch (RuntimeException e) {
            log.error("Agent call guard audit failed: category={}", category, e);
        }
    }

    /** Forgets the counts of keys that made no request for a while, when there are many. */
    private void trim() {
        if (calls.size() < CAPACITY) {
            return;
        }
        Instant since = clock.instant().minus(MINUTE);
        calls.entrySet().removeIf(entry -> {
            synchronized (entry.getValue()) {
                Instant last = entry.getValue().peekLast();
                return last == null || !last.isAfter(since);
            }
        });
    }
}
