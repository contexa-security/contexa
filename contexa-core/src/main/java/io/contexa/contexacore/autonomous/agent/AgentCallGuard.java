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
import java.util.Collections;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The call limits and the denial alarm of agents (docs/agent A5-7, AG-11e; OWASP ASI02, ASI08; MCP rate limiting).
 * Every request of an agent is counted for its delegation (one person's work, the agent's decision key) and for the
 * agent across everyone it acts for, over the last minute. Past a limit the request is slowed down, or the agent is
 * stopped as a BLOCK stops it; within the limits, and for people, nothing changes. An agent whose requests are refused
 * unusually often raises an alarm: audited, and its accountable person told. The counts are this instance's.
 */
@Slf4j
public class AgentCallGuard {

    /** The answer to a request past a limit. */
    public static final String CALL_LIMIT = "AGENT_CALL_LIMIT";

    /** What a request of an agent may do under the limits. */
    public record Admission(boolean admitted, @Nullable String scope, int calls, int limit, long retryAfterSeconds) {

        static final Admission IN_LIMITS = new Admission(true, null, 0, 0, 0);
    }

    static final Duration MINUTE = Duration.ofMinutes(1);
    static final int CAPACITY = 20_000;
    /** QF-42: how many keys of each count one call looks at for a count whose window has passed. */
    static final int FORGET_STEP = 4;

    private final SecurityZeroTrustProperties.CallLimit limits;
    private final SecurityZeroTrustProperties.DenialAlarm alarm;
    private final AgentNotices notices;
    private final AgentRegistry registry;
    private final CentralAuditFacade audit;
    private final Clock clock;
    private final Map<String, Deque<Instant>> calls = new ConcurrentHashMap<>();
    private final Map<String, Deque<Outcome>> outcomes = new ConcurrentHashMap<>();
    private final Map<String, Instant> lastReported = new ConcurrentHashMap<>();
    /** Where the forgetting of idle counts goes on (QF-42); used by one call at a time. */
    private final ReentrantLock forgetting = new ReentrantLock();
    private Iterator<String> callKeys = Collections.emptyIterator();
    private Iterator<String> outcomeKeys = Collections.emptyIterator();
    private Iterator<String> reportKeys = Collections.emptyIterator();
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
            for (String idle : outcomes.keySet()) {
                forgetIfIdle(outcomes, idle, Outcome::at, old);
            }
        }
        forgetIdle(now);
        int[] counted = new int[2];
        // Counted within the key's entry, so forgetting an idle key cannot drop this outcome (QF-42).
        outcomes.compute(key, (ignored, recent) -> {
            Deque<Outcome> window = recent != null ? recent : new ArrayDeque<>();
            synchronized (window) {
                window.addLast(new Outcome(now, denied));
                Instant since = now.minus(alarm.getWindow());
                while (!window.isEmpty() && !window.peekFirst().at().isAfter(since)) {
                    window.pollFirst();
                }
                counted[0] = window.size();
                counted[1] = (int) window.stream().filter(Outcome::denied).count();
            }
            return window;
        });
        int requests = counted[0];
        int refused = counted[1];
        if (requests >= alarm.getMinRequests() && (double) refused / requests >= alarm.getRate()
                && reportDue("alarm:" + key, now, alarm.getWindow())) {
            raiseAlarm(subject, requests, refused);
        }
    }

    private int count(String key, Instant now) {
        trim();
        forgetIdle(now);
        Instant since = now.minus(MINUTE);
        int[] counted = new int[1];
        // Counted within the key's entry, so forgetting an idle key cannot drop this call (QF-42).
        calls.compute(key, (ignored, recent) -> {
            Deque<Instant> window = recent != null ? recent : new ArrayDeque<>();
            synchronized (window) {
                while (!window.isEmpty() && !window.peekFirst().isAfter(since)) {
                    window.pollFirst();
                }
                window.addLast(now);
                counted[0] = window.size();
            }
            return window;
        });
        return counted[0];
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

    int trackedCallKeys() {
        return calls.size();
    }

    int trackedOutcomeKeys() {
        return outcomes.size();
    }

    int trackedReportKeys() {
        return lastReported.size();
    }

    /** Forgets the counts of keys that made no request for a while, when there are many. */
    private void trim() {
        if (calls.size() < CAPACITY) {
            return;
        }
        Instant since = clock.instant().minus(MINUTE);
        for (String idle : calls.keySet()) {
            forgetIfIdle(calls, idle, Function.identity(), since);
        }
    }

    /**
     * QF-42: forgets, a few keys on each call and whatever the infrastructure mode, the counts whose newest entry left
     * its window (a minute for the calls, the alarm window for the outcomes) and the report times past their interval.
     * Such a count or time answers as no entry does, so no limit, alarm or report reads anything else; a call that
     * finds another one forgetting goes on without.
     */
    private void forgetIdle(Instant now) {
        if (!forgetting.tryLock()) {
            return;
        }
        try {
            Instant callsSince = now.minus(MINUTE);
            Instant outcomesSince = now.minus(alarm.getWindow());
            callKeys = forgetStep(calls, callKeys, key -> forgetIfIdle(calls, key, Function.identity(), callsSince));
            outcomeKeys = forgetStep(outcomes, outcomeKeys, key -> forgetIfIdle(outcomes, key, Outcome::at,
                    outcomesSince));
            reportKeys = forgetStep(lastReported, reportKeys, key -> lastReported.computeIfPresent(key,
                    (ignored, last) -> last.plus(key.startsWith("alarm:") ? alarm.getWindow() : MINUTE)
                            .isAfter(now) ? last : null));
        } finally {
            forgetting.unlock();
        }
    }

    /** Looks at the next {@link #FORGET_STEP} keys after {@code cursor}, from the first again once all were seen. */
    private static Iterator<String> forgetStep(Map<String, ?> counts, Iterator<String> cursor,
                                               Consumer<String> forget) {
        Iterator<String> keys = cursor.hasNext() ? cursor : counts.keySet().iterator();
        for (int looked = 0; looked < FORGET_STEP && keys.hasNext(); looked++) {
            forget.accept(keys.next());
        }
        return keys;
    }

    /** Removes the key's count when its newest entry is not after {@code since}, unless a call counts in between. */
    private static <T> void forgetIfIdle(Map<String, Deque<T>> counts, String key, Function<T, Instant> at,
                                         Instant since) {
        counts.computeIfPresent(key, (ignored, window) -> {
            synchronized (window) {
                T last = window.peekLast();
                return last == null || !at.apply(last).isAfter(since) ? null : window;
            }
        });
    }
}
