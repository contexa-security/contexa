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
package io.contexa.contexacommon.security.bridge.identity;

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * What resolving the identities of requests came to, counted: by outcome, by source and by problem. Each problem is
 * reported to the application's log at most once a minute, with what it means and what the application can do, and never
 * with a user's id or mail address. The counts are what a console or a start report reads ({@link #snapshot()}).
 */
@Slf4j
public final class IdentityDiagnostics {

    private static final long REPORT_INTERVAL_MILLIS = 60_000L;

    private final Map<ContexaIdentity.Outcome, AtomicLong> outcomes = counters(ContexaIdentity.Outcome.class);
    private final Map<ContexaIdentity.Source, AtomicLong> sources = counters(ContexaIdentity.Source.class);
    private final Map<SubjectProblem, AtomicLong> problems = counters(SubjectProblem.class);
    private final Map<SubjectProblem, AtomicLong> lastReports = counters(SubjectProblem.class);
    private final LongSupplier clock;

    public IdentityDiagnostics() {
        this(System::currentTimeMillis);
    }

    IdentityDiagnostics(LongSupplier clock) {
        this.clock = clock;
        lastReports.values().forEach(last -> last.set(Long.MIN_VALUE / 2));
    }

    private static <E extends Enum<E>> Map<E, AtomicLong> counters(Class<E> type) {
        EnumMap<E, AtomicLong> counters = new EnumMap<>(type);
        for (E key : type.getEnumConstants()) {
            counters.put(key, new AtomicLong());
        }
        return counters;
    }

    /** Counts the identity a request resolved to. */
    public void record(ContexaIdentity identity) {
        outcomes.get(identity.getOutcome()).incrementAndGet();
        if (identity.getSource() != null) {
            sources.get(identity.getSource()).incrementAndGet();
        }
    }

    /**
     * Counts a problem met while resolving a request's identity, and reports it when it was not reported in the last
     * minute.
     *
     * @param detail what tells the application where to look (a class, a field, a time), never a user's id or address
     */
    public void problem(SubjectProblem problem, @Nullable String detail) {
        problem(problem, detail, null);
    }

    /** As {@link #problem(SubjectProblem, String)}, with the failure behind it. */
    public void problem(SubjectProblem problem, @Nullable String detail, @Nullable Throwable failure) {
        long count = problems.get(problem).incrementAndGet();
        if (!due(problem)) {
            return;
        }
        String message = "[Contexa] Bridge: " + meaning(problem) + (detail != null ? " (" + detail + ")" : "") + ". "
                + advice(problem) + " [" + problem + ", " + count + " so far]";
        if (failure != null) {
            log.error(message, failure);
        } else {
            log.error(message);
        }
    }

    private boolean due(SubjectProblem problem) {
        AtomicLong last = lastReports.get(problem);
        long now = clock.getAsLong();
        long previous = last.get();
        return now - previous >= REPORT_INTERVAL_MILLIS && last.compareAndSet(previous, now);
    }

    /** The counts so far. */
    public Snapshot snapshot() {
        return new Snapshot(values(ContexaIdentity.Outcome.class, outcomes), values(ContexaIdentity.Source.class, sources),
                values(SubjectProblem.class, problems));
    }

    private static <E extends Enum<E>> Map<E, Long> values(Class<E> type, Map<E, AtomicLong> counters) {
        Map<E, Long> values = new EnumMap<>(type);
        counters.forEach((key, count) -> values.put(key, count.get()));
        return Collections.unmodifiableMap(values);
    }

    private static String meaning(SubjectProblem problem) {
        return switch (problem) {
            case USER_ID_BLANK, USER_ID_TOO_LONG, USER_ID_CONTROL_CHARACTER ->
                    "the user the application named has a user id that breaks the rule, so the request goes on without"
                            + " a Contexa identity";
            case EMAIL_MISSING, EMAIL_MALFORMED, EMAIL_TOO_LONG ->
                    "the user the application named has no usable mail address, so Contexa cannot send it a"
                            + " verification code";
            case DISPLAY_NAME_DROPPED, ORGANIZATION_DROPPED, TENANT_DROPPED, SESSION_KEY_DROPPED, AUTHORITIES_TRIMMED,
                 AUTHENTICATION_FIELD_DROPPED, DELEGATION_DROPPED ->
                    "an optional value of the user the application named breaks its rule and was left out";
            case UNSUPPORTED_PRINCIPAL ->
                    "the signed-in Spring Security principal is of none of the kinds Spring Security names a user by,"
                            + " so the request goes on without a Contexa identity";
            case MAPPER_FAILED -> "the application's ContexaSubjectMapper failed, and the request went on";
            case RESOLVER_FAILED -> "the application's ContexaSubjectResolver failed, and the request went on without a"
                    + " Contexa identity";
            case RESOLVER_SLOW -> "the application's ContexaSubjectResolver took long";
            case EMAIL_PROVIDER_FAILED -> "the application's BridgeUserEmailProvider failed";
            case SOURCES_DISAGREE -> "two sources of one request named two different users; Contexa took the first in"
                    + " the order of contexa.bridge.identity-sources";
            case NOT_A_SUBJECT -> "the request attribute ctxa.subject holds something that is no ContexaSubject, so it"
                    + " was not read";
        };
    }

    private static String advice(SubjectProblem problem) {
        return switch (problem) {
            case USER_ID_BLANK, USER_ID_TOO_LONG, USER_ID_CONTROL_CHARACTER ->
                    "A user id is required: not blank, at most 255 characters, without control characters.";
            case EMAIL_MISSING, EMAIL_MALFORMED, EMAIL_TOO_LONG ->
                    "Give the address in the ContexaSubject, in an email claim of the token, or through a"
                            + " BridgeUserEmailProvider bean.";
            case DISPLAY_NAME_DROPPED, ORGANIZATION_DROPPED, TENANT_DROPPED, SESSION_KEY_DROPPED, AUTHORITIES_TRIMMED,
                 AUTHENTICATION_FIELD_DROPPED, DELEGATION_DROPPED ->
                    "See the limits of ContexaSubject in the legacy integration standard.";
            case UNSUPPORTED_PRINCIPAL ->
                    "Contexa reads no fields of an application's own principal: add a ContexaSubjectMapper bean that"
                            + " names the user.";
            case MAPPER_FAILED, RESOLVER_FAILED, EMAIL_PROVIDER_FAILED ->
                    "Contexa caught the failure; the application's request was not affected.";
            case RESOLVER_SLOW -> "The resolver runs on every request: read the application's sign-in state without"
                    + " waiting for a remote call.";
            case SOURCES_DISAGREE -> "Name the user in one place, or set contexa.bridge.identity-sources.";
            case NOT_A_SUBJECT -> "Put a ContexaSubject under ctxa.subject, built with ContexaSubject.of(userId, email).";
        };
    }

    /** The counts of the outcomes, the sources and the problems. */
    public record Snapshot(Map<ContexaIdentity.Outcome, Long> outcomes, Map<ContexaIdentity.Source, Long> sources,
                           Map<SubjectProblem, Long> problems) {
    }
}
