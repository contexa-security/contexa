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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The identity Contexa resolved for a request (bridge v2): an immutable value of the request's scope with the user the
 * application named ({@link ContexaSubject}), where it came from ({@link Source}), the outcome ({@link Outcome}) and what
 * broke the legacy integration standard ({@link SubjectProblem}). Contexa keeps it under
 * {@link BridgeRequestAttributes#SUBJECT_IDENTITY}; {@link #current} reads it.
 * <p>
 * Until the readers of an identity move to this value (bridge v2 step B4), the static methods below keep the rule of
 * R-10 of docs/agent/운영모드-정상화-구현계획.md, the user Contexa decides a request for, and the one rule that names the
 * subject of an authentication:
 * <ul>
 *   <li>The application's signed-in user, when its security context holds one: Contexa reads it and never replaces it.</li>
 *   <li>Else the user the bridge resolved for Contexa alone ({@link BridgeRequestAttributes#IDENTITY}): a legacy
 *       application that signs its users in without Spring Security, through its session, a request attribute or an
 *       explicit handoff. It lives in the request only, so the application's security context stays as it left it.</li>
 *   <li>Else the security context as it is: nobody, or an anonymous visitor, as before.</li>
 * </ul>
 * Where Contexa signs the application's users in itself (FULL), its chain writes the security context and the bridge
 * keeps no identity of its own, so this is the security context's user.
 */
@Slf4j
public final class ContexaIdentity {

    private static final Set<Class<?>> UNNAMED_PRINCIPALS_REPORTED = ConcurrentHashMap.newKeySet();
    private static final ContexaIdentity ABSENT = new ContexaIdentity(null, null, Outcome.ABSENT, Set.of(), null);

    /** Where the identity of a request came from. */
    public enum Source {
        /** The application's Spring Security signed the user in, and its security context holds the user. */
        SPRING_SECURITY,
        /** The application's {@code ContexaSubjectResolver} named the user. */
        RESOLVER,
        /** The application put the user under {@link ContexaSubject#REQUEST_ATTRIBUTE}. */
        REQUEST_ATTRIBUTE,
        /** One of Contexa's own accounts: the console's administrator, or a user Contexa's main chain signs in. */
        CONTEXA_ACCOUNT
    }

    /** What resolving the identity of a request came to. */
    public enum Outcome {
        /** A user, perhaps without a mail address. */
        RESOLVED,
        /** Nobody signed in to the request. */
        ABSENT,
        /** The application named a user that breaks the standard: the request goes on without a Contexa identity. */
        INVALID,
        /** The application's resolver or mapper failed: the request goes on without a Contexa identity. */
        FAILED
    }

    @Nullable
    private final ContexaSubject subject;
    @Nullable
    private final Source source;
    private final Outcome outcome;
    private final Set<SubjectProblem> problems;
    @Nullable
    private final Authentication authentication;

    private ContexaIdentity(@Nullable ContexaSubject subject, @Nullable Source source, Outcome outcome,
                            Set<SubjectProblem> problems, @Nullable Authentication authentication) {
        this.subject = subject;
        this.source = source;
        this.outcome = outcome;
        this.problems = problems;
        this.authentication = authentication;
    }

    /**
     * A resolved identity.
     *
     * @param authentication the application's signed-in authentication it was read from (Spring Security or one of
     *                       Contexa's accounts), whose standard token facts the decisions read; {@code null} otherwise
     */
    public static ContexaIdentity resolved(ContexaSubject subject, Source source, Collection<SubjectProblem> problems,
                                           @Nullable Authentication authentication) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(source, "source");
        if (!subject.hasUserId()) {
            throw new IllegalArgumentException("A subject without a user id is no resolved identity");
        }
        return new ContexaIdentity(subject, source, Outcome.RESOLVED, copy(problems), authentication);
    }

    /** An identity that did not resolve: nobody, a user that breaks the standard, or a failure. */
    public static ContexaIdentity unresolved(Outcome outcome, Collection<SubjectProblem> problems) {
        Objects.requireNonNull(outcome, "outcome");
        if (outcome == Outcome.RESOLVED) {
            throw new IllegalArgumentException("A resolved identity has a subject");
        }
        if (outcome == Outcome.ABSENT && problems.isEmpty()) {
            return ABSENT;
        }
        return new ContexaIdentity(null, null, outcome, copy(problems), null);
    }

    /** A request nobody signed in to. */
    public static ContexaIdentity absent() {
        return ABSENT;
    }

    /** The identity Contexa resolved for a request; {@code null} when it resolved none yet. */
    @Nullable
    public static ContexaIdentity current(@Nullable HttpServletRequest request) {
        return request != null && request.getAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY) instanceof ContexaIdentity identity
                ? identity
                : null;
    }

    private static Set<SubjectProblem> copy(Collection<SubjectProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return Set.of();
        }
        return Collections.unmodifiableSet(EnumSet.copyOf(problems));
    }

    /** The user, when the identity resolved. */
    @Nullable
    public ContexaSubject getSubject() {
        return subject;
    }

    /** The user id, when the identity resolved. */
    @Nullable
    public String getUserId() {
        return subject != null ? subject.getUserId() : null;
    }

    @Nullable
    public Source getSource() {
        return source;
    }

    public Outcome getOutcome() {
        return outcome;
    }

    /** What broke the standard on the way, whether the identity resolved or not. */
    public Set<SubjectProblem> getProblems() {
        return problems;
    }

    /** The application's signed-in authentication the identity was read from, when it came from one. */
    @Nullable
    public Authentication getAuthentication() {
        return authentication;
    }

    public boolean isResolved() {
        return outcome == Outcome.RESOLVED;
    }

    /** Whether the identity resolved without a mail address a verification code can be sent to. */
    public boolean isEmailMissing() {
        return subject != null && !subject.hasEmail();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ContexaIdentity that
                && Objects.equals(subject, that.subject)
                && source == that.source
                && outcome == that.outcome
                && problems.equals(that.problems)
                && Objects.equals(authentication, that.authentication);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, source, outcome, problems, authentication);
    }

    @Override
    public String toString() {
        return "ContexaIdentity[outcome=" + outcome + ", source=" + source + ", subject=" + subject + ", problems="
                + problems + "]";
    }

    /** The user a request is decided for; the application's security context when the request is unknown. */
    @Nullable
    public static Authentication of(@Nullable HttpServletRequest request) {
        Authentication application = SecurityContextHolder.getContext().getAuthentication();
        if (signedIn(application) || request == null) {
            return application;
        }
        return request.getAttribute(BridgeRequestAttributes.IDENTITY) instanceof Authentication bridged && signedIn(bridged)
                ? bridged
                : application;
    }

    /**
     * The user id Contexa decides a request for (bridge v2): the identity it resolved for the request
     * ({@link #current}), so a user the application's {@code ContexaSubjectMapper} or resolver named is the one keyed;
     * without a resolved identity (a request the bridge filter has not seen yet, or a user the application signed in
     * after it), the subject of the request's authentication ({@link #of}, {@link #subjectId}); null when the request
     * names nobody.
     */
    @Nullable
    public static String userId(@Nullable HttpServletRequest request) {
        ContexaIdentity identity = current(request);
        if (identity != null && identity.isResolved()) {
            return identity.getUserId();
        }
        Authentication authentication = of(request);
        return signedIn(authentication) ? subjectId(authentication) : null;
    }

    /**
     * The user id Contexa decides a request for, with the principal the caller holds standing in when the request has no
     * resolved identity: the identity Contexa resolved for the request ({@link #current}), else the subject of the given
     * authentication ({@link #subjectId}). For a caller that is handed the authentication, such as a sign-in, where the
     * security context may not hold that authentication yet, or a controller given its principal; null when neither
     * names a user (an anonymous visitor names none). A principal that is no authentication, such as the servlet
     * container's signed-in user, is named by its standard {@link Principal#getName()}.
     */
    @Nullable
    public static String userId(@Nullable HttpServletRequest request, @Nullable Principal principal) {
        ContexaIdentity identity = current(request);
        if (identity != null && identity.isResolved()) {
            return identity.getUserId();
        }
        if (principal == null || principal instanceof AnonymousAuthenticationToken) {
            return null;
        }
        if (principal instanceof Authentication authentication) {
            return subjectId(authentication);
        }
        String name = principal.getName();
        String stripped = name != null ? name.strip() : "";
        return stripped.isEmpty() ? null : stripped;
    }

    /**
     * What names the sign-in of a request for an application without sessions: the session key of the identity Contexa
     * resolved for it ({@code ContexaSubject.getSessionKey()}, the {@code sid} claim of a token); null when it states none.
     */
    @Nullable
    public static String sessionKey(@Nullable HttpServletRequest request) {
        ContexaIdentity identity = current(request);
        return identity != null && identity.isResolved() && identity.getSubject() != null
                ? identity.getSubject().getSessionKey()
                : null;
    }

    /**
     * The subject an authentication's decisions are keyed by: its name, trimmed, as Spring Security gives it (a token's
     * principal claim, {@code sub} by default; a user's username), for the kinds Spring Security names a user by. Every
     * reader of a subject from an authentication alone uses this, so one person is one subject whichever way the request
     * came; null when it names nobody. A reader that has the request uses {@link #userId}.
     * <p>
     * A principal of none of those kinds (an application's own object, a map) is named by its {@code toString()} only,
     * which for such an object differs from one request to the next or carries every field. Contexa does not read its
     * fields (bridge v2): it names no subject, the application is told once for each class, and the application names
     * the user with a {@code ContexaSubjectMapper}.
     */
    @Nullable
    public static String subjectId(@Nullable Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        String name = authentication.getName();
        Object principal = authentication.getPrincipal();
        if (namedByItsText(principal, name)) {
            if (UNNAMED_PRINCIPALS_REPORTED.add(principal.getClass())) {
                log.error("[Contexa] The signed-in principal of type {} is none of the kinds Spring Security names a user"
                                + " by, so Contexa does not know who it is and reads none of its fields. Add a"
                                + " ContexaSubjectMapper bean that names the user, or sign the user in with a UserDetails.",
                        principal.getClass().getName());
            }
            return null;
        }
        if (name == null) {
            return null;
        }
        String trimmed = name.strip();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static boolean namedByItsText(@Nullable Object principal, @Nullable String name) {
        return principal != null && name != null
                && !(principal instanceof UserDetails)
                && !(principal instanceof AuthenticatedPrincipal)
                && !(principal instanceof Principal)
                && !(principal instanceof CharSequence)
                && name.equals(principal.toString());
    }

    /** Whether an authentication is a signed-in user: authenticated, and no anonymous visitor. */
    public static boolean signedIn(@Nullable Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
