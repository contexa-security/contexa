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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * How many decisions of a new context one person may ask the model for in a short window: a call from another session,
 * address or browser than the person's decision was reached for. It asks the model before its answer counts (a call from
 * a changed context waits for its verdict), so without a limit whoever holds a password or a session buys a model call
 * with every new browser string. A person changes context a few times an hour; one whose context keeps changing within
 * a minute is the signal itself. Past the limit the model is not asked: the caller answers the call with a CHALLENGE for
 * itself alone. Nothing past the limit is let through for want of a decision.
 * <p>
 * The window slides and counts only the decisions it gave; a refusal takes no place in it. The count is this server's
 * and lives in memory, whichever store the decisions use: on several servers each counts for itself, so what a person
 * can cause grows with the servers and stays bounded, and every call is decided or refused. Reaching the limit is logged
 * and audited once a minute for the person.
 */
@Slf4j
public class NewContextDecisionLimit {

    /** What asks for the decision. */
    public enum Kind {
        /** A person's call from another session, address or browser than the decision on record. */
        CHANGED_CONTEXT
    }

    static final Duration DEFAULT_WINDOW = Duration.ofMinutes(1);
    static final Duration REPORT_INTERVAL = Duration.ofMinutes(1);
    /** The people counted at once; past it those whose window ends first are forgotten first. */
    static final int PEOPLE_KEPT = 100_000;

    private final int decisions;
    private final Duration window;
    private final CentralAuditFacade audit;
    private final Clock clock;
    /** The times of the decisions each person took in the window, oldest first. */
    private final ExpiringKeySpace<long[]> taken;
    private final ExpiringKeySpace<Boolean> reported;

    public NewContextDecisionLimit(@Nullable SecurityZeroTrustProperties.NewContextLimit settings,
                                   @Nullable CentralAuditFacade audit, @Nullable Clock clock) {
        SecurityZeroTrustProperties.NewContextLimit given = settings != null
                ? settings : new SecurityZeroTrustProperties.NewContextLimit();
        Clock time = clock != null ? clock : Clock.systemUTC();
        this.clock = time;
        this.decisions = given.getDecisions();
        this.window = windowOf(given.getWindow());
        this.audit = audit;
        this.taken = ExpiringKeySpace.<long[]>builder(time).ttl(this.window).bound(PEOPLE_KEPT).build();
        this.reported = ExpiringKeySpace.<Boolean>builder(time).ttl(REPORT_INTERVAL).bound(PEOPLE_KEPT).build();
    }

    private static Duration windowOf(@Nullable Duration configured) {
        if (configured != null && !configured.isZero() && !configured.isNegative()) {
            return configured;
        }
        log.error("[ZeroTrust] contexa.security.zerotrust.analysis.new-context-limit.window {} is not a positive time, "
                + "{} is used", configured, DEFAULT_WINDOW);
        return DEFAULT_WINDOW;
    }

    /** Whether a limit is set: decisions of 0 or less set none. */
    public boolean limits() {
        return decisions > 0;
    }

    /**
     * Takes one of the person's decisions of a new context: true when the window had one left, false, reported once a
     * minute for the person, when it had none.
     *
     * @param key the key the person's decisions are stored under
     */
    public boolean take(String key, Kind kind) {
        if (!limits() || key == null || key.isBlank()) {
            return true;
        }
        Boolean granted = taken.atomically(key, slot -> {
            long nowMs = clock.millis();
            long since = nowMs - window.toMillis();
            long[] held = slot.value() != null ? slot.value() : new long[0];
            long[] inWindow = Arrays.stream(held).filter(at -> at > since).toArray();
            if (inWindow.length >= decisions) {
                if (inWindow.length != held.length) {
                    slot.setUntil(inWindow, inWindow[inWindow.length - 1] + window.toMillis());
                }
                return Boolean.FALSE;
            }
            long[] next = Arrays.copyOf(inWindow, inWindow.length + 1);
            next[inWindow.length] = nowMs;
            slot.setUntil(next, nowMs + window.toMillis());
            return Boolean.TRUE;
        });
        if (Boolean.TRUE.equals(granted)) {
            return true;
        }
        reportOnceAMinute(key, kind);
        return false;
    }

    private void reportOnceAMinute(String key, Kind kind) {
        if (!reported.putIfAbsent(key, Boolean.TRUE)) {
            return;
        }
        String what = "a call from a changed context is refused with a CHALLENGE of its own";
        log.warn("[ZeroTrust] {} passed {} decisions of a new context in {}s: {}; the model is not asked until the "
                + "window has room (reported once a minute)", key, decisions, window.toSeconds(), what);
        if (audit == null) {
            return;
        }
        try {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("kind", kind.name());
            details.put("decisions", decisions);
            details.put("windowSeconds", window.toSeconds());
            audit.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.DECISION_LIMIT_REACHED)
                    .principalName(key)
                    .resourceIdentifier(key)
                    .eventSource("CORE")
                    .action(AuditEventCategory.DECISION_LIMIT_REACHED.name())
                    .decision("CHALLENGE")
                    .outcome("MODEL_NOT_ASKED")
                    .reason("Passed " + decisions + " decisions of a new context in " + window.toSeconds()
                            + " seconds: " + what)
                    .details(details)
                    .build());
        } catch (RuntimeException e) {
            log.error("[ZeroTrust] The decision limit could not be audited: key={}", key, e);
        }
    }
}
