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

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectResolver;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserEmailProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.AntPathMatcher;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The one function that makes the identity of a request (bridge v2): the sources of {@link Settings#order()} are tried
 * in turn, and the first that names a user Contexa can identify gives the identity. A source with nothing for the request
 * is skipped. Nothing of it fails the application's request: a failure of the application's resolver or mapper is caught,
 * counted and reported, and the request goes on without a Contexa identity.
 * <ul>
 *   <li>{@code spring-security}: the signed-in user of the application's Spring Security, one of Contexa's own accounts
 *       first, then the application's {@link ContexaSubjectMapper}, then the standard kinds.</li>
 *   <li>{@code resolver}: the application's {@link ContexaSubjectResolver}, given a read-only view of the request and
 *       measured. It is called at most once for a request, and never after a source before it named the user.</li>
 *   <li>{@code request-attribute}: the {@link ContexaSubject} the application put under
 *       {@link ContexaSubject#REQUEST_ATTRIBUTE}. It is read even after a source before it named the user, so two sources
 *       naming two users are reported.</li>
 * </ul>
 */
public final class IdentityResolution {

    private static final AntPathMatcher PATHS = new AntPathMatcher();

    private final Settings settings;
    @Nullable
    private final ContexaSubjectResolver resolver;
    @Nullable
    private final ContexaSubjectMapper mapper;
    @Nullable
    private final BridgeUserEmailProvider emailProvider;
    private final Accounts accounts;
    private final IdentityDiagnostics diagnostics;

    public IdentityResolution(Settings settings, @Nullable ContexaSubjectResolver resolver,
                              @Nullable ContexaSubjectMapper mapper, @Nullable BridgeUserEmailProvider emailProvider,
                              Accounts accounts, IdentityDiagnostics diagnostics) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.resolver = resolver;
        this.mapper = mapper;
        this.emailProvider = emailProvider;
        this.accounts = accounts != null ? accounts : Accounts.NONE;
        this.diagnostics = diagnostics != null ? diagnostics : new IdentityDiagnostics();
    }

    /** The resolution of an application that declared nothing for the bridge: no resolver, no mapper, no provider. */
    public static IdentityResolution standard() {
        return new IdentityResolution(Settings.defaults(), null, null, null, Accounts.NONE, new IdentityDiagnostics());
    }

    public Settings settings() {
        return settings;
    }

    public IdentityDiagnostics diagnostics() {
        return diagnostics;
    }

    /** Whether the application declared a resolver. */
    public boolean hasResolver() {
        return resolver != null;
    }

    /**
     * The identity of a request, from every source.
     *
     * @param application the authentication of the application's security context, when there is one
     */
    public ContexaIdentity resolve(HttpServletRequest request, @Nullable Authentication application) {
        return resolve(request, application, true);
    }

    /**
     * The identity of a request again, without calling the resolver (which is called once a request): for a user the
     * application made known after Contexa's place in its filters, at a decision or at a sign-in.
     */
    public ContexaIdentity resolveAgainWithoutTheResolver(HttpServletRequest request, @Nullable Authentication application) {
        return resolve(request, application, false);
    }

    /**
     * bridge v2 B5-2, ContexaBridge.signedIn: the identity of a user the application named for the request itself, by the
     * same rules as a user it puts in the request attribute ({@link ContexaSubject#REQUEST_ATTRIBUTE}), its mail address
     * from the mail address provider included.
     */
    public ContexaIdentity named(ContexaSubject subject) {
        Found problems = new Found();
        Attempt attempt = subject != null
                ? validated(withProvidedEmail(subject, problems), ContexaIdentity.Source.REQUEST_ATTRIBUTE, null, problems)
                : Attempt.ABSENT;
        ContexaIdentity identity = attempt.outcome() == ContexaIdentity.Outcome.RESOLVED
                ? ContexaIdentity.resolved(attempt.subject(), attempt.source(), problems.all(), null)
                : ContexaIdentity.unresolved(attempt.outcome(), problems.all());
        diagnostics.record(identity);
        return identity;
    }

    private ContexaIdentity resolve(HttpServletRequest request, @Nullable Authentication application, boolean callResolver) {
        Found problems = new Found();
        Attempt first = null;
        ContexaIdentity.Outcome worst = ContexaIdentity.Outcome.ABSENT;
        for (ContexaIdentity.Source source : settings.order()) {
            if (first != null && source != ContexaIdentity.Source.REQUEST_ATTRIBUTE) {
                continue;
            }
            if (source == ContexaIdentity.Source.RESOLVER && !callResolver) {
                continue;
            }
            Attempt attempt = attempt(source, request, application, problems);
            if (attempt.outcome() == ContexaIdentity.Outcome.RESOLVED) {
                if (first == null) {
                    first = attempt;
                } else if (!Objects.equals(first.subject().getUserId(), attempt.subject().getUserId())) {
                    problems.add(SubjectProblem.SOURCES_DISAGREE, first.source() + " and " + attempt.source(), null);
                }
            } else if (first == null) {
                worst = worse(worst, attempt.outcome());
            }
        }
        ContexaIdentity identity = first != null
                ? ContexaIdentity.resolved(first.subject(), first.source(), problems.all(), first.authentication())
                : ContexaIdentity.unresolved(worst, problems.all());
        diagnostics.record(identity);
        return identity;
    }

    private Attempt attempt(ContexaIdentity.Source source, HttpServletRequest request,
                            @Nullable Authentication application, Found problems) {
        return switch (source) {
            case SPRING_SECURITY, CONTEXA_ACCOUNT -> springSecurity(request, application, problems);
            case RESOLVER -> resolver(request, problems);
            case REQUEST_ATTRIBUTE -> requestAttribute(request, problems);
        };
    }

    private Attempt springSecurity(HttpServletRequest request, @Nullable Authentication application, Found problems) {
        if (!ContexaIdentity.signedIn(application)) {
            return Attempt.ABSENT;
        }
        String account = accounts.accountName(application);
        if (account != null) {
            return validated(SpringSecuritySubjects.account(application, account, request),
                    ContexaIdentity.Source.CONTEXA_ACCOUNT, application, problems);
        }
        if (mapper != null) {
            Optional<ContexaSubject> mapped;
            try {
                mapped = mapper.map(application);
            } catch (Exception | LinkageError | StackOverflowError failure) {
                problems.add(SubjectProblem.MAPPER_FAILED, mapper.getClass().getName(), failure);
                return Attempt.FAILED;
            }
            if (mapped != null && mapped.isPresent()) {
                return validated(mapped.get(), ContexaIdentity.Source.SPRING_SECURITY, application, problems);
            }
        }
        if (!SpringSecuritySubjects.standardKind(application)) {
            Object principal = application.getPrincipal();
            problems.add(SubjectProblem.UNSUPPORTED_PRINCIPAL,
                    "principal of type " + (principal != null ? principal.getClass().getName() : "null"), null);
            return Attempt.INVALID;
        }
        ContexaSubject subject = SpringSecuritySubjects.read(application, request, settings.emailSources(), emailProvider,
                problems);
        return validated(subject, ContexaIdentity.Source.SPRING_SECURITY, application, problems);
    }

    private Attempt resolver(HttpServletRequest request, Found problems) {
        if (resolver == null || excluded(request)) {
            return Attempt.ABSENT;
        }
        long started = System.nanoTime();
        Optional<ContexaSubject> answer;
        try {
            answer = resolver.resolve(new ServletRequestView(request));
        } catch (Exception | LinkageError | StackOverflowError failure) {
            problems.add(SubjectProblem.RESOLVER_FAILED, resolver.getClass().getName(), failure);
            return Attempt.FAILED;
        } finally {
            Duration took = Duration.ofNanos(System.nanoTime() - started);
            if (took.compareTo(settings.resolverSlowThreshold()) > 0) {
                problems.add(SubjectProblem.RESOLVER_SLOW, resolver.getClass().getName() + " took " + took.toMillis()
                        + " ms, threshold " + settings.resolverSlowThreshold().toMillis() + " ms", null);
            }
        }
        if (answer == null || answer.isEmpty()) {
            return Attempt.ABSENT;
        }
        return validated(withProvidedEmail(answer.get(), problems), ContexaIdentity.Source.RESOLVER, null, problems);
    }

    /**
     * A user the application named without a mail address gets the one its mail address provider knows, when the mail
     * sources name the provider: the same rule as for a Spring Security user, whichever way the user was named.
     */
    private ContexaSubject withProvidedEmail(ContexaSubject subject, Found problems) {
        if (subject.hasEmail() || !subject.hasUserId() || emailProvider == null
                || !settings.emailSources().contains(SpringSecuritySubjects.PROVIDER_SOURCE)) {
            return subject;
        }
        String provided = SpringSecuritySubjects.provided(subject.getUserId(), emailProvider, problems);
        return provided != null ? subject.withEmail(provided) : subject;
    }

    private Attempt requestAttribute(HttpServletRequest request, Found problems) {
        Object value = request.getAttribute(ContexaSubject.REQUEST_ATTRIBUTE);
        if (value == null) {
            return Attempt.ABSENT;
        }
        if (!(value instanceof ContexaSubject subject)) {
            problems.add(SubjectProblem.NOT_A_SUBJECT, value.getClass().getName(), null);
            return Attempt.INVALID;
        }
        return validated(withProvidedEmail(subject, problems), ContexaIdentity.Source.REQUEST_ATTRIBUTE, null, problems);
    }

    private Attempt validated(ContexaSubject subject, ContexaIdentity.Source source, @Nullable Authentication authentication,
                              Found problems) {
        for (SubjectProblem problem : subject.getProblems()) {
            problems.add(problem, "named by " + name(source), null);
        }
        return subject.hasUserId()
                ? new Attempt(ContexaIdentity.Outcome.RESOLVED, subject, source, authentication)
                : Attempt.INVALID;
    }

    private boolean excluded(HttpServletRequest request) {
        if (settings.resolverExcludePaths().isEmpty()) {
            return false;
        }
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();
        String path = (servletPath != null ? servletPath : "") + (pathInfo != null ? pathInfo : "");
        for (String pattern : settings.resolverExcludePaths()) {
            if (PATHS.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    private static ContexaIdentity.Outcome worse(ContexaIdentity.Outcome kept, ContexaIdentity.Outcome met) {
        return rank(met) > rank(kept) ? met : kept;
    }

    private static int rank(ContexaIdentity.Outcome outcome) {
        return switch (outcome) {
            case FAILED -> 3;
            case INVALID -> 2;
            case ABSENT -> 1;
            case RESOLVED -> 0;
        };
    }

    /** The name of a source in {@code contexa.bridge.identity-sources}. */
    public static String name(ContexaIdentity.Source source) {
        return switch (source) {
            case SPRING_SECURITY -> "spring-security";
            case RESOLVER -> "resolver";
            case REQUEST_ATTRIBUTE -> "request-attribute";
            case CONTEXA_ACCOUNT -> "contexa-account";
        };
    }

    private record Attempt(ContexaIdentity.Outcome outcome, @Nullable ContexaSubject subject,
                           @Nullable ContexaIdentity.Source source, @Nullable Authentication authentication) {

        static final Attempt ABSENT = new Attempt(ContexaIdentity.Outcome.ABSENT, null, null, null);
        static final Attempt INVALID = new Attempt(ContexaIdentity.Outcome.INVALID, null, null, null);
        static final Attempt FAILED = new Attempt(ContexaIdentity.Outcome.FAILED, null, null, null);
    }

    /** The problems of one resolution: each counted and reported once. */
    private final class Found implements SpringSecuritySubjects.Problems {

        private final EnumSet<SubjectProblem> problems = EnumSet.noneOf(SubjectProblem.class);

        @Override
        public void add(SubjectProblem problem, @Nullable String detail, @Nullable Throwable failure) {
            if (problems.add(problem)) {
                diagnostics.problem(problem, detail, failure);
            }
        }

        @Override
        public Set<SubjectProblem> all() {
            return problems;
        }
    }

    /** One of Contexa's own accounts, told from an authentication. */
    @FunctionalInterface
    public interface Accounts {

        /** No authentication is one of Contexa's accounts. */
        Accounts NONE = authentication -> null;

        /** The name of the Contexa account the authentication is of, or {@code null} when it is none. */
        @Nullable
        String accountName(Authentication authentication);
    }

    /**
     * How the identity of a request is made.
     *
     * @param order                 the sources, in the order they are tried
     * @param emailSources          where a Spring Security user's mail address comes from, in order
     * @param resolverExcludePaths  the paths the resolver is not called for (Ant patterns on the servlet path)
     * @param resolverSlowThreshold a resolver call taking longer is reported
     */
    public record Settings(List<ContexaIdentity.Source> order, List<String> emailSources,
                           List<String> resolverExcludePaths, Duration resolverSlowThreshold) {

        public Settings {
            order = List.copyOf(order);
            emailSources = List.copyOf(emailSources);
            resolverExcludePaths = List.copyOf(resolverExcludePaths);
            Objects.requireNonNull(resolverSlowThreshold, "resolverSlowThreshold");
        }

        /** The settings of an application that set nothing. */
        public static Settings defaults() {
            return of(new BridgeProperties());
        }

        /**
         * The settings the application's properties give.
         *
         * @throws IllegalStateException when a source is unknown or none is left, so the start says what to set
         */
        public static Settings of(BridgeProperties properties) {
            return new Settings(order(properties.getIdentitySources()), emailSources(properties.getEmailSources()),
                    paths(properties.getResolver().getExcludePaths()), threshold(properties.getResolver().getSlowThreshold()));
        }

        private static List<ContexaIdentity.Source> order(@Nullable List<String> names) {
            LinkedHashSet<ContexaIdentity.Source> order = new LinkedHashSet<>();
            for (String name : names != null ? names : List.<String>of()) {
                String normalized = name != null ? name.trim().toLowerCase(Locale.ROOT) : "";
                ContexaIdentity.Source source = switch (normalized) {
                    case "spring-security" -> ContexaIdentity.Source.SPRING_SECURITY;
                    case "resolver" -> ContexaIdentity.Source.RESOLVER;
                    case "request-attribute" -> ContexaIdentity.Source.REQUEST_ATTRIBUTE;
                    default -> throw new IllegalStateException("contexa.bridge.identity-sources names an unknown source '"
                            + name + "': use spring-security, resolver and request-attribute, in the order to try them");
                };
                order.add(source);
            }
            if (order.isEmpty()) {
                throw new IllegalStateException("contexa.bridge.identity-sources names no source, so Contexa would know no"
                        + " user of any request: name at least one of spring-security, resolver and request-attribute");
            }
            return new ArrayList<>(order);
        }

        private static List<String> emailSources(@Nullable List<String> names) {
            List<String> sources = new ArrayList<>();
            for (String name : names != null ? names : List.<String>of()) {
                String trimmed = name != null ? name.trim() : "";
                if (SpringSecuritySubjects.PROVIDER_SOURCE.equalsIgnoreCase(trimmed)) {
                    sources.add(SpringSecuritySubjects.PROVIDER_SOURCE);
                } else if (trimmed.regionMatches(true, 0, SpringSecuritySubjects.CLAIM_SOURCE_PREFIX, 0,
                        SpringSecuritySubjects.CLAIM_SOURCE_PREFIX.length())
                        && trimmed.length() > SpringSecuritySubjects.CLAIM_SOURCE_PREFIX.length()) {
                    sources.add(SpringSecuritySubjects.CLAIM_SOURCE_PREFIX
                            + trimmed.substring(SpringSecuritySubjects.CLAIM_SOURCE_PREFIX.length()).trim());
                } else {
                    throw new IllegalStateException("contexa.bridge.email-sources names an unknown source '" + name
                            + "': use claim:<claim name> and provider, in the order to try them");
                }
            }
            return Collections.unmodifiableList(sources);
        }

        private static List<String> paths(@Nullable List<String> patterns) {
            List<String> paths = new ArrayList<>();
            for (String pattern : patterns != null ? patterns : List.<String>of()) {
                if (pattern != null && !pattern.isBlank()) {
                    paths.add(pattern.trim());
                }
            }
            return paths;
        }

        private static Duration threshold(@Nullable Duration threshold) {
            if (threshold == null || threshold.isNegative()) {
                throw new IllegalStateException("contexa.bridge.resolver.slow-threshold must be zero or more");
            }
            return threshold;
        }
    }
}
