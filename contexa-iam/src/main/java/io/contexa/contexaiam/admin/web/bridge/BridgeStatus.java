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
package io.contexa.contexaiam.admin.web.bridge;

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * What the console's user bridge status screen shows: the counts {@link IdentityDiagnostics} kept on this node since the
 * application started, as the shares of the outcomes and of the sources and as the problems met. Every outcome, source,
 * problem and effect has its words in the bundles under {@value #PREFIX}; the screen reads them by the keys this value
 * names, so the screen and its tests share one rule for them.
 *
 * @param available     whether the application has the bridge diagnostics; without them nothing was counted
 * @param checks        the resolutions of a request's user counted, whatever their outcome
 * @param resolved      the resolutions that named a user, the whole the sources share
 * @param outcomes      every outcome in the order of {@link ContexaIdentity.Outcome}, with its share of the checks
 * @param sources       every source in the order of {@link ContexaIdentity.Source}, with its share of the resolved
 * @param emailProblems the problems that left a user without a mail address a verification code can be sent to
 * @param problems      the problems met, the most frequent first
 * @param quietProblems the problems not met, in the order of {@link SubjectProblem}
 */
public record BridgeStatus(boolean available, long checks, long resolved, List<Share> outcomes, List<Share> sources,
                           long emailProblems, List<Problem> problems, List<Problem> quietProblems) {

    /** The prefix of every key of the screen's words. */
    public static final String PREFIX = "admin.bridge.status.";

    static final String OUTCOME = "outcome";
    static final String SOURCE = "source";

    private static final Object[] NO_ARGUMENTS = new Object[0];

    /** The screen of an application without the bridge diagnostics: nothing was counted. */
    public static BridgeStatus off() {
        return new BridgeStatus(false, 0L, 0L, List.of(), List.of(), 0L, List.of(), List.of());
    }

    /** The screen of the counts so far; {@link #off()} when there are none to read. */
    public static BridgeStatus of(@Nullable IdentityDiagnostics.Snapshot snapshot) {
        if (snapshot == null) {
            return off();
        }
        Map<ContexaIdentity.Outcome, Long> outcomeCounts = snapshot.outcomes();
        long checks = total(outcomeCounts);
        long resolved = count(outcomeCounts, ContexaIdentity.Outcome.RESOLVED);

        List<Share> outcomes = new ArrayList<>();
        for (ContexaIdentity.Outcome outcome : ContexaIdentity.Outcome.values()) {
            long count = count(outcomeCounts, outcome);
            outcomes.add(new Share(OUTCOME, outcome.name(), count, share(count, checks),
                    breaksTheRequestIdentity(outcome) && count > 0));
        }

        List<Share> sources = new ArrayList<>();
        for (ContexaIdentity.Source source : ContexaIdentity.Source.values()) {
            long count = count(snapshot.sources(), source);
            sources.add(new Share(SOURCE, source.name(), count, share(count, resolved), false));
        }

        List<Problem> problems = new ArrayList<>();
        List<Problem> quietProblems = new ArrayList<>();
        long emailProblems = 0L;
        for (SubjectProblem kind : SubjectProblem.values()) {
            long count = count(snapshot.problems(), kind);
            Problem problem = new Problem(kind, count);
            if (count > 0) {
                problems.add(problem);
            } else {
                quietProblems.add(problem);
            }
            if (kind.breaksTheEmail()) {
                emailProblems += count;
            }
        }
        problems.sort(Comparator.comparingLong(Problem::count).reversed()
                .thenComparing(problem -> problem.kind().ordinal()));

        return new BridgeStatus(true, checks, resolved, List.copyOf(outcomes), List.copyOf(sources), emailProblems,
                List.copyOf(problems), List.copyOf(quietProblems));
    }

    /** Whether any resolution was counted. */
    public boolean counted() {
        return checks > 0;
    }

    /** The resolutions whose user broke the standard: the requests went on without a Contexa identity. */
    public long invalid() {
        return outcomeCount(ContexaIdentity.Outcome.INVALID);
    }

    /** The resolutions the application's resolver or mapper failed: the requests went on without a Contexa identity. */
    public long failed() {
        return outcomeCount(ContexaIdentity.Outcome.FAILED);
    }

    /** Whether a resolution broke the standard or failed, which the screen shows before anything else. */
    public boolean attention() {
        return invalid() > 0 || failed() > 0;
    }

    /** The mail address problems, met or not, in the order of {@link SubjectProblem}. */
    public List<Problem> emailBreakdown() {
        List<Problem> breakdown = new ArrayList<>();
        for (Problem problem : problems) {
            if (problem.kind().breaksTheEmail()) {
                breakdown.add(problem);
            }
        }
        for (Problem problem : quietProblems) {
            if (problem.kind().breaksTheEmail()) {
                breakdown.add(problem);
            }
        }
        breakdown.sort(Comparator.comparingInt(problem -> problem.kind().ordinal()));
        return List.copyOf(breakdown);
    }

    private long outcomeCount(ContexaIdentity.Outcome outcome) {
        for (Share share : outcomes) {
            if (share.code().equals(outcome.name())) {
                return share.count();
            }
        }
        return 0L;
    }

    private static boolean breaksTheRequestIdentity(ContexaIdentity.Outcome outcome) {
        return outcome == ContexaIdentity.Outcome.INVALID || outcome == ContexaIdentity.Outcome.FAILED;
    }

    private static <E extends Enum<E>> long count(@Nullable Map<E, Long> counts, E key) {
        if (counts == null) {
            return 0L;
        }
        Long count = counts.get(key);
        return count != null && count > 0 ? count : 0L;
    }

    private static <E extends Enum<E>> long total(@Nullable Map<E, Long> counts) {
        if (counts == null) {
            return 0L;
        }
        long total = 0L;
        for (Long count : counts.values()) {
            if (count != null && count > 0) {
                total += count;
            }
        }
        return total;
    }

    private static double share(long count, long whole) {
        return whole > 0 ? (double) count / whole : 0.0d;
    }

    /** The key of a word of the screen. */
    static String key(String... parts) {
        return PREFIX + String.join(".", parts);
    }

    /**
     * An outcome or a source with its count and its share of the whole it belongs to.
     *
     * @param family {@code outcome} or {@code source}
     * @param code   the name of the outcome or the source, as the integration standard writes it
     * @param alert  whether the screen marks it: an outcome that left requests without a Contexa identity
     */
    public record Share(String family, String code, long count, double share, boolean alert) {

        public String nameKey() {
            return key(family, code, "name");
        }

        public String descriptionKey() {
            return key(family, code, "desc");
        }

        /** The values the words of the row are formatted with. */
        public Object[] args() {
            return SOURCE.equals(family) && ContexaIdentity.Source.REQUEST_ATTRIBUTE.name().equals(code)
                    ? new Object[] {ContexaSubject.REQUEST_ATTRIBUTE}
                    : NO_ARGUMENTS;
        }
    }

    /** A problem of the integration standard with the times it was met, and what it did to the resolution. */
    public record Problem(SubjectProblem kind, long count) {

        public String code() {
            return kind.name();
        }

        public Effect effect() {
            return Effect.of(kind);
        }

        public String nameKey() {
            return key("problem", code(), "name");
        }

        public String meaningKey() {
            return key("problem", code(), "meaning");
        }

        public String actionKey() {
            return key("problem", code(), "action");
        }

        /**
         * The values the words of the problem are formatted with: the limits of {@link ContexaSubject} and of
         * {@link ContexaAuthentication} the problem is about, and the request attribute an application names its user
         * under, so the words never state a limit the code does not keep.
         */
        public Object[] args() {
            return switch (kind) {
                case USER_ID_BLANK, USER_ID_TOO_LONG, USER_ID_CONTROL_CHARACTER, EMAIL_TOO_LONG, ORGANIZATION_DROPPED,
                     TENANT_DROPPED, SESSION_KEY_DROPPED, DELEGATION_DROPPED ->
                        new Object[] {ContexaSubject.MAX_TEXT_LENGTH};
                case DISPLAY_NAME_DROPPED -> new Object[] {ContexaSubject.MAX_DISPLAY_NAME_LENGTH};
                case AUTHORITIES_TRIMMED -> new Object[] {ContexaSubject.MAX_AUTHORITIES, ContexaSubject.MAX_TEXT_LENGTH};
                case AUTHENTICATION_FIELD_DROPPED -> new Object[] {ContexaAuthentication.MAX_LENGTH};
                case NOT_A_SUBJECT -> new Object[] {ContexaSubject.REQUEST_ATTRIBUTE};
                case EMAIL_MISSING, EMAIL_MALFORMED, UNSUPPORTED_PRINCIPAL, MAPPER_FAILED, RESOLVER_FAILED,
                     RESOLVER_SLOW, EMAIL_PROVIDER_FAILED, SOURCES_DISAGREE -> NO_ARGUMENTS;
            };
        }
    }

    /**
     * What a problem did to the resolution it was met in, as {@code IdentityResolution} handles it: the user of that
     * source was not taken (a user id that breaks its rule, a principal Contexa does not read, an attribute that holds no
     * subject, a mapper or a resolver that failed), the user has no mail address to send a code to, an optional value was
     * left out, or the resolution went on as it was.
     */
    public enum Effect {
        USER_NOT_RESOLVED,
        NO_EMAIL,
        VALUE_LEFT_OUT,
        NOTICE;

        public String key() {
            return BridgeStatus.key("effect", name());
        }

        static Effect of(SubjectProblem problem) {
            return switch (problem) {
                case USER_ID_BLANK, USER_ID_TOO_LONG, USER_ID_CONTROL_CHARACTER, UNSUPPORTED_PRINCIPAL, NOT_A_SUBJECT,
                     MAPPER_FAILED, RESOLVER_FAILED -> USER_NOT_RESOLVED;
                case EMAIL_MISSING, EMAIL_MALFORMED, EMAIL_TOO_LONG, EMAIL_PROVIDER_FAILED -> NO_EMAIL;
                case DISPLAY_NAME_DROPPED, ORGANIZATION_DROPPED, TENANT_DROPPED, SESSION_KEY_DROPPED,
                     AUTHORITIES_TRIMMED, AUTHENTICATION_FIELD_DROPPED, DELEGATION_DROPPED -> VALUE_LEFT_OUT;
                case RESOLVER_SLOW, SOURCES_DISAGREE -> NOTICE;
            };
        }
    }
}
