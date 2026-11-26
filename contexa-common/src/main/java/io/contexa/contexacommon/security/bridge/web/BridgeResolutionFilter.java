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
package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.authentication.HostPrincipalSnapshotAdapter;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.identity.SubjectStamps;
import io.contexa.contexacommon.security.bridge.resolver.AuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.AuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.DelegationStampResolver;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

public class BridgeResolutionFilter extends OncePerRequestFilter {

    private static final long REPORT_INTERVAL_MILLIS = 60_000L;

    private final BridgeProperties properties;
    private final RequestContextCollector requestContextCollector;
    private final List<AuthenticationStampResolver> authenticationStampResolvers;
    private final List<AuthorizationStampResolver> authorizationStampResolvers;
    private final List<DelegationStampResolver> delegationStampResolvers;
    private final BridgeCoverageEvaluator bridgeCoverageEvaluator;
    private final BridgeRuntimeSupport bridgeRuntimeSupport;
    private final AtomicLong failures = new AtomicLong();
    private final AtomicLong lastReport = new AtomicLong();
    @Nullable
    private final SecurityContextRepository securityContextRepository;
    private final IdentityResolution identityResolution;

    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator) {
        this(
                properties,
                requestContextCollector,
                authenticationStampResolvers,
                authorizationStampResolvers,
                delegationStampResolvers,
                bridgeCoverageEvaluator,
                null,
                null,
                null
        );
    }

    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService) {
        this(
                properties,
                requestContextCollector,
                authenticationStampResolvers,
                authorizationStampResolvers,
                delegationStampResolvers,
                bridgeCoverageEvaluator,
                bridgeUserMirrorSyncService,
                null,
                null
        );
    }

    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService,
            @Nullable BridgeRuntimeSupport bridgeRuntimeSupport,
            @Nullable SecurityContextRepository securityContextRepository) {
        this(
                properties,
                requestContextCollector,
                authenticationStampResolvers,
                authorizationStampResolvers,
                delegationStampResolvers,
                bridgeCoverageEvaluator,
                bridgeUserMirrorSyncService,
                bridgeRuntimeSupport,
                securityContextRepository,
                null
        );
    }

    /**
     * @param identityResolution how the identity of a request is made (bridge v2); without one, the resolution of an
     *                           application that declared nothing for the bridge
     */
    public BridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            List<AuthenticationStampResolver> authenticationStampResolvers,
            List<AuthorizationStampResolver> authorizationStampResolvers,
            List<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator,
            @Nullable BridgeUserMirrorSyncService bridgeUserMirrorSyncService,
            @Nullable BridgeRuntimeSupport bridgeRuntimeSupport,
            @Nullable SecurityContextRepository securityContextRepository,
            @Nullable IdentityResolution identityResolution) {
        this.identityResolution = identityResolution != null ? identityResolution : IdentityResolution.standard();
        this.properties = properties != null ? properties : new BridgeProperties();
        this.requestContextCollector = requestContextCollector;
        this.authenticationStampResolvers = authenticationStampResolvers != null ? List.copyOf(authenticationStampResolvers) : List.of();
        this.authorizationStampResolvers = authorizationStampResolvers != null ? List.copyOf(authorizationStampResolvers) : List.of();
        this.delegationStampResolvers = delegationStampResolvers != null ? List.copyOf(delegationStampResolvers) : List.of();
        this.bridgeCoverageEvaluator = bridgeCoverageEvaluator;
        this.bridgeRuntimeSupport = bridgeRuntimeSupport != null
                ? bridgeRuntimeSupport
                : new BridgeRuntimeSupport(this.properties, bridgeUserMirrorSyncService);
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.isEnabled();
    }

    /**
     * Makes the identity of the request (bridge v2, {@link IdentityResolution}) and keeps it under
     * {@link BridgeRequestAttributes#SUBJECT_IDENTITY}. A request of the application's signed-in Spring Security user is
     * then resolved for that user as before; where Contexa keeps an identity of its own (SANDBOX, R-10), a request the
     * application's Spring Security signed nobody in to is resolved for the user the application named for Contexa alone
     * (its resolver or the request attribute), and the security context stays empty.
     * <p>
     * This filter only observes the application's request. Whatever goes wrong while the principal, the request and the
     * stamps are read (an authentication without a name, a resolver that fails, a mirror that cannot be written) must
     * never become the application's error: the request goes on. The application's own exceptions in the chain are not
     * caught here.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        try {
            ContexaIdentity identity = identityResolution.resolve(request, auth);
            request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
            if (ContexaIdentity.signedIn(auth)) {
                resolveForTheRequest(request, response, auth, false);
            } else if (keepsAnIdentityOfItsOwn()) {
                resolveForContexaAlone(request, identity);
            }
        } catch (Exception | LinkageError | StackOverflowError e) {
            reportFailure(e);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * R-10: the user a protected method is decided for, made known after this filter ran (an application that signs the
     * user in to Spring Security, or puts the user in the request attribute, in an MVC interceptor or a controller).
     * Called at the decision; a request resolved for its user already is left as it is, and the application's resolver,
     * called once a request, is not called again. Only where Contexa keeps an identity of its own (SANDBOX): under FULL,
     * Contexa's chain signs the users in. Nothing of it may fail the call.
     */
    public void resolveAtDecision(@Nullable HttpServletRequest request) {
        if (request == null || shouldNotFilter(request) || !keepsAnIdentityOfItsOwn()) {
            return;
        }
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (ContexaIdentity.signedIn(auth)) {
                if (request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT) != null
                        && request.getAttribute(BridgeRequestAttributes.IDENTITY) == null) {
                    return;
                }
                request.removeAttribute(BridgeRequestAttributes.IDENTITY);
                request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                        identityResolution.resolveAgainWithoutTheResolver(request, auth));
                resolveForTheRequest(request, null, auth, false);
            } else if (!(request.getAttribute(BridgeRequestAttributes.IDENTITY) instanceof Authentication)) {
                ContexaIdentity identity = identityResolution.resolveAgainWithoutTheResolver(request, auth);
                if (identity.isResolved()) {
                    request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
                    resolveForContexaAlone(request, identity);
                }
            }
        } catch (Exception | LinkageError | StackOverflowError e) {
            reportFailure(e);
        }
    }

    /** Where Contexa does not write the application's security context, its decisions read an identity of its own. */
    private boolean keepsAnIdentityOfItsOwn() {
        return !properties.operatingBehaviour().writesSecurityContext();
    }

    /**
     * A request without a signed-in user of the application's Spring Security: the user the application named for
     * Contexa alone (its resolver or the request attribute) becomes Contexa's identity of the request, with the
     * authorization its authorities state and the delegation it states. Nothing the application did not name is read: a
     * request whose identity did not resolve is left exactly as it came.
     */
    private void resolveForContexaAlone(HttpServletRequest request, ContexaIdentity identity) {
        if (!identity.isResolved()
                || (identity.getSource() != ContexaIdentity.Source.RESOLVER
                && identity.getSource() != ContexaIdentity.Source.REQUEST_ATTRIBUTE)) {
            return;
        }
        recordNamed(request, identity, false);
    }

    /**
     * bridge v2 B5-2, ContexaBridge.signedIn: the application tells Contexa that the user it names signed in on this
     * request. The user becomes Contexa's identity of the request, as one the application names in the request attribute
     * does, and the sign-in waits for the copy of the user (within the guard's bound), which writes when and from where the
     * user signed in. A request on Contexa's own paths is left alone, as at any sign-in.
     *
     * @return the identity the subject made; unresolved when its user id breaks the rules, and nothing else is done then
     */
    public ContexaIdentity signedIn(HttpServletRequest request, ContexaSubject subject) {
        ContexaIdentity identity = identityResolution.named(subject);
        if (shouldNotFilter(request)) {
            return identity;
        }
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
        if (identity.isResolved()) {
            recordNamed(request, identity, true);
        }
        return identity;
    }

    private void recordNamed(HttpServletRequest request, ContexaIdentity identity, boolean signIn) {
        RequestContextSnapshot requestContext = requestContextCollector.collect(request);
        AuthenticationStamp authenticationStamp = SubjectStamps.authenticationStamp(identity, requestContext);
        AuthorizationStamp authorizationStamp = bridgeRuntimeSupport.deriveAuthorizationStamp(
                authenticationStamp, requestContext.requestUri(), requestContext.method()).orElse(null);
        DelegationStamp delegationStamp = SubjectStamps.delegationStamp(identity).orElse(null);
        Resolution resolution = record(request, null, null, requestContext, authenticationStamp, authorizationStamp,
                delegationStamp, signIn);
        bridgeRuntimeSupport.bindRequestIdentity(request, resolution.result(), resolution.userSync());
    }

    /**
     * The stamps of a sign-in. This filter met the request before its authentication existed, and a sign-in usually ends
     * the request there, so whoever sends the sign-in for analysis asks for them: the resolution of any request, with the
     * authentication the sign-in put in the security context. Nothing of it may fail the sign-in. The sign-in is where the
     * copy of the application's user is made, so it waits for it (within the guard's bound), and the requests after it
     * find the copy kept.
     */
    public void resolveSignIn(HttpServletRequest request, Authentication authentication) {
        if (shouldNotFilter(request)) {
            return;
        }
        try {
            request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                    identityResolution.resolveAgainWithoutTheResolver(request, authentication));
            resolveForTheRequest(request, null, authentication, true);
        } catch (Exception | LinkageError | StackOverflowError e) {
            reportFailure(e);
        }
    }

    private void reportFailure(Throwable failure) {
        long now = System.currentTimeMillis();
        long count = failures.incrementAndGet();
        long last = lastReport.get();
        if (now - last >= REPORT_INTERVAL_MILLIS && lastReport.compareAndSet(last, now)) {
            logger.warn("Contexa could not read this request's authentication and let the request go on ("
                    + count + " so far): " + failure, failure);
        }
    }

    private void resolveForTheRequest(HttpServletRequest request, @Nullable HttpServletResponse response, Authentication auth,
                                      boolean signIn) {
        request.setAttribute(
                BridgeRequestAttributes.HOST_PRINCIPAL_SNAPSHOT,
                HostPrincipalSnapshotAdapter.INSTANCE.snapshot(auth));
        RequestContextSnapshot requestContext = requestContextCollector.collect(request);
        AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request, requestContext).orElse(null);
        record(request, response, auth, requestContext, authenticationStamp, signIn);
    }

    /**
     * The stamps of the request beside its authentication stamp, and the copy of its user, written to the request. The
     * application's request never waits for Contexa's database for the copy of its user; a sign-in does.
     */
    private Resolution record(HttpServletRequest request, @Nullable HttpServletResponse response, @Nullable Authentication auth,
                              RequestContextSnapshot requestContext, @Nullable AuthenticationStamp authenticationStamp,
                              boolean signIn) {
        AuthorizationStamp authorizationStamp = resolveAuthorizationStamp(request, requestContext)
                .or(() -> bridgeRuntimeSupport.deriveAuthorizationStamp(authenticationStamp, requestContext.requestUri(), requestContext.method()))
                .orElse(null);
        DelegationStamp delegationStamp = resolveDelegationStamp(request, requestContext).orElse(null);
        return record(request, response, auth, requestContext, authenticationStamp, authorizationStamp, delegationStamp,
                signIn);
    }

    private Resolution record(HttpServletRequest request, @Nullable HttpServletResponse response, @Nullable Authentication auth,
                              RequestContextSnapshot requestContext, @Nullable AuthenticationStamp authenticationStamp,
                              @Nullable AuthorizationStamp authorizationStamp, @Nullable DelegationStamp delegationStamp,
                              boolean signIn) {
        BridgeUserMirrorSyncResult userSyncResult = bridgeRuntimeSupport.synchronizeUser(
                auth, authenticationStamp, authorizationStamp, requestContext, signIn);

        BridgeResolutionResult result = new BridgeResolutionResult(
                requestContext,
                authenticationStamp,
                authorizationStamp,
                delegationStamp,
                bridgeCoverageEvaluator.evaluate(authenticationStamp, authorizationStamp, delegationStamp)
        );

        bridgeRuntimeSupport.writeResolutionAttributes(request, result, userSyncResult);
        bridgeRuntimeSupport.populateSecurityContext(authenticationStamp, result, userSyncResult, false);
        if (authenticationStamp != null && authenticationStamp.authenticated()) {
            bridgeRuntimeSupport.persistSecurityContext(securityContextRepository, request, response);
        }
        return new Resolution(result, userSyncResult);
    }

    private record Resolution(BridgeResolutionResult result, @Nullable BridgeUserMirrorSyncResult userSync) {
    }

    private Optional<AuthenticationStamp> resolveAuthenticationStamp(HttpServletRequest request, RequestContextSnapshot requestContext) {
        for (AuthenticationStampResolver resolver : authenticationStampResolvers) {
            Optional<AuthenticationStamp> resolved = resolver.resolve(request, requestContext, properties);
            if (resolved.isPresent() && resolved.get().principalId() != null && !resolved.get().principalId().isBlank()) {
                return resolved;
            }
        }
        return Optional.empty();
    }

    private Optional<AuthorizationStamp> resolveAuthorizationStamp(HttpServletRequest request, RequestContextSnapshot requestContext) {
        List<AuthorizationStamp> candidates = new ArrayList<>();
        for (AuthorizationStampResolver resolver : authorizationStampResolvers) {
            Optional<AuthorizationStamp> resolved = resolver.resolve(request, requestContext, properties);
            if (resolved.isPresent()) {
                candidates.add(resolved.get());
            }
        }
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        boolean conflict = hasExplicitEffectConflict(candidates);
        AuthorizationStamp selected = selectBestAuthorizationEvidence(candidates, conflict);
        return Optional.of(mergeAuthorizationEvidence(candidates, selected, conflict));
    }

    private boolean hasExplicitEffectConflict(List<AuthorizationStamp> candidates) {
        boolean allow = candidates.stream().anyMatch(stamp -> stamp.effect() == AuthorizationEffect.ALLOW);
        boolean deny = candidates.stream().anyMatch(stamp -> stamp.effect() == AuthorizationEffect.DENY);
        return allow && deny;
    }

    private AuthorizationStamp selectBestAuthorizationEvidence(List<AuthorizationStamp> candidates, boolean conflict) {
        AuthorizationStamp selected = null;
        int selectedScore = Integer.MIN_VALUE;
        for (AuthorizationStamp candidate : candidates) {
            if (conflict && candidate.effect() != AuthorizationEffect.DENY) {
                continue;
            }
            int score = authorizationEvidenceScore(candidate);
            if (selected == null || score > selectedScore) {
                selected = candidate;
                selectedScore = score;
            }
        }
        return selected != null ? selected : candidates.get(0);
    }

    private int authorizationEvidenceScore(AuthorizationStamp stamp) {
        int score = stamp.effect() != AuthorizationEffect.UNKNOWN ? 100 : 0;
        String source = stamp.decisionSource();
        if ("SECURITY_CONTEXT".equalsIgnoreCase(source)) {
            score += 40;
        } else if ("SESSION".equalsIgnoreCase(source)) {
            score += 30;
        } else if ("REQUEST_ATTRIBUTE".equalsIgnoreCase(source)) {
            score += 20;
        } else if ("HEADER".equalsIgnoreCase(source)) {
            score += 10;
        } else if ("AUTHENTICATION_DERIVED".equalsIgnoreCase(source)) {
            score += 5;
        }
        score += hasText(stamp.policyId()) ? 4 : 0;
        score += hasText(stamp.policyVersion()) ? 2 : 0;
        score += stamp.privileged() != null ? 2 : 0;
        score += !stamp.scopeTags().isEmpty() ? 1 : 0;
        score += !stamp.effectiveRoles().isEmpty() ? 1 : 0;
        score += !stamp.effectiveAuthorities().isEmpty() ? 1 : 0;
        return score;
    }

    private AuthorizationStamp mergeAuthorizationEvidence(
            List<AuthorizationStamp> candidates,
            AuthorizationStamp selected,
            boolean conflict) {
        LinkedHashSet<String> scopeTags = new LinkedHashSet<>();
        LinkedHashSet<String> roles = new LinkedHashSet<>();
        LinkedHashSet<String> authorities = new LinkedHashSet<>();
        LinkedHashSet<String> evidenceSources = new LinkedHashSet<>();
        LinkedHashSet<String> conflictEvidence = new LinkedHashSet<>();
        Boolean privileged = null;
        String policyId = selected.policyId();
        String policyVersion = selected.policyVersion();

        for (AuthorizationStamp candidate : candidates) {
            scopeTags.addAll(candidate.scopeTags());
            roles.addAll(candidate.effectiveRoles());
            authorities.addAll(candidate.effectiveAuthorities());
            if (hasText(candidate.decisionSource())) {
                evidenceSources.add(candidate.decisionSource());
            }
            if (candidate.effect() != AuthorizationEffect.UNKNOWN) {
                conflictEvidence.add(candidate.decisionSource() + ":" + candidate.effect().name());
            }
            if (Boolean.TRUE.equals(candidate.privileged())) {
                privileged = true;
            } else if (privileged == null && Boolean.FALSE.equals(candidate.privileged())) {
                privileged = false;
            }
            policyId = firstNonBlank(policyId, candidate.policyId());
            policyVersion = firstNonBlank(policyVersion, candidate.policyVersion());
        }

        Map<String, Object> attributes = new LinkedHashMap<>(selected.attributes());
        attributes.put("authorizationEvidenceSources", List.copyOf(evidenceSources));
        attributes.put("authorizationEvidenceCount", candidates.size());
        if (conflict) {
            attributes.put("authorizationConflict", true);
            attributes.put("authorizationConflictResolution", "DENY_FAIL_SAFE");
            attributes.put("authorizationConflictEvidence", List.copyOf(conflictEvidence));
        }

        return new AuthorizationStamp(
                selected.subjectId(),
                selected.resourceId(),
                selected.action(),
                conflict ? AuthorizationEffect.DENY : selected.effect(),
                privileged,
                List.copyOf(scopeTags),
                policyId,
                policyVersion,
                conflict ? "CONFLICT_FAIL_SAFE" : selected.decisionSource(),
                selected.decisionTime(),
                List.copyOf(roles),
                List.copyOf(authorities),
                attributes
        );
    }

    private String firstNonBlank(String first, String second) {
        return hasText(first) ? first : second;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private Optional<DelegationStamp> resolveDelegationStamp(HttpServletRequest request, RequestContextSnapshot requestContext) {
        for (DelegationStampResolver resolver : delegationStampResolvers) {
            Optional<DelegationStamp> resolved = resolver.resolve(request, requestContext, properties);
            if (resolved.isPresent()) {
                return resolved;
            }
        }
        return Optional.empty();
    }
}
