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
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.annotation.ResourceImportance;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacore.autonomous.context.support.ResourceImportanceResolver;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.security.HostOwnedIdentityNotice;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import io.contexa.contexacommon.security.ConsoleSession;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.function.Supplier;

@Slf4j
public class AuthorizationManagerMethodInterceptor
        implements MethodInterceptor, AuthorizationAdvisor, SmartInitializingSingleton {

    private final Pointcut pointcut;
    private ProtectableMethodAuthorizationManager authorizationManager;
    private DelegatorAuthority delegatorAuthority;
    private ProtectableRapidReentryGuard rapidReentryGuard;
    /**
     * Sets the collaborators once: the advisor is created while post-processors are registered (the auto-proxy creator
     * looks its advisors up then), and resolving its collaborators then would create their whole graph early.
     */
    private volatile Runnable collaboratorResolver;
    private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();
    private final int order = AuthorizationInterceptorsOrder.FIRST.getOrder() + 1;
    private final Supplier<SecurityContextHolderStrategy> securityContextHolderStrategy = SecurityContextHolder::getContextHolderStrategy;
    private ZeroTrustEventPublisher zeroTrustEventPublisher;
    private AuthorizationMetrics metricsCollector;
    private SynchronousProtectableDecisionService synchronousProtectableDecisionService;
    private SecurityZeroTrustProperties securityZeroTrustProperties;
    private ProtectableResourceCertificationGate protectableResourceCertificationGate;
    private ProtectableLlmSuppressionWriter protectableLlmSuppressionWriter;
    private AuthorizationDenialRecorder authorizationDenialRecorder;
    private ContexaStores contexaStores = new ContexaStores();
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    public AuthorizationManagerMethodInterceptor(
            Pointcut pointcut,
            ProtectableMethodAuthorizationManager authorizationManager,
            ProtectableRapidReentryGuard rapidReentryGuard) {
        this.pointcut = pointcut;
        this.authorizationManager = authorizationManager;
        this.rapidReentryGuard = rapidReentryGuard;
    }

    /** An advisor whose collaborators are set by the collaborator resolver, before its first call. */
    public AuthorizationManagerMethodInterceptor(Pointcut pointcut, Runnable collaboratorResolver) {
        this.pointcut = pointcut;
        this.collaboratorResolver = collaboratorResolver;
    }

    /** Resolves the collaborators once every singleton exists, so a missing one still fails the start. */
    @Override
    public void afterSingletonsInstantiated() {
        resolveCollaborators();
    }

    private void resolveCollaborators() {
        if (collaboratorResolver == null) {
            return;
        }
        synchronized (this) {
            Runnable resolver = collaboratorResolver;
            if (resolver != null) {
                resolver.run();
                collaboratorResolver = null;
            }
        }
    }

    @Override
    public Object invoke(MethodInvocation mi) throws Throwable {
        resolveCollaborators();
        if (hasNoUserToDecide()) {
            recordRanWithoutUser(mi);
            return proceed(mi);
        }
        Authentication authentication = getAuthentication();
        // Ownership design S-7: report once an application that signs users in after Contexa's request filters.
        HostOwnedIdentityNotice.reportAtProtectedMethod(currentRequest(), authentication);
        boolean granted = false;
        boolean publishEvent = true;
        String denialReason = null;
        boolean invoked = false;
        String executionFailure = null;
        String checkFailure = null;
        Protectable protectable = resolveProtectable(mi);
        // Q-17: where a console session lifts a restriction no decision stands in its way.
        boolean llmAnalysisAllowed = isLlmAnalysisAllowed() && !ConsoleSession.onReleasePath(currentRequest());
        boolean rapidReentryAllowed = true;

        RequestPathScope.enter();
        try {
            if (!llmAnalysisAllowed) {
                publishEvent = false;
                log.debug("[ZeroTrust] AI decision analysis is disabled for Protectable invocation. mode={}",
                        securityZeroTrustMode());
            } else {
                rapidReentryAllowed = rapidReentryGuard.tryAcquire(authentication, mi, securityZeroTrustMode());
                if (!rapidReentryAllowed && (protectable == null || !protectable.sync())) {
                    publishEvent = false;
                    recordSuppressedProtectable(authentication, mi, "RAPID_REENTRY_ACTOR_SESSION");
                    log.debug("[ZeroTrust] Rapid re-entry detected for async protectable. Access will proceed and analysis will be skipped.");
                } else if (!rapidReentryAllowed) {
                    publishEvent = false;
                    recordSuppressedProtectable(authentication, mi, "RAPID_REENTRY_ACTOR_SESSION_SYNC");
                    if (isEnforcementDisabled()) {
                        log.debug("[ZeroTrust][SHADOW] Actor-session protectable analysis is already in progress. Access will proceed and duplicate analysis will be skipped.");
                    } else {
                        throw ZeroTrustAccessDeniedException.analysisRequired(actorSessionDecisionScopeId());
                    }
                }
            }

            try {
                authorizationManager.protectable(() -> authentication, mi);
            } catch (RuntimeException unfinished) {
                if (!StoreFailures.isStoreFailure(unfinished)) {
                    throw unfinished;
                }
                // A store that did not answer says nothing about the user: the method policies stay unknown, and the call
                // goes on as the operating mode specifies (Q-7) unless its resource is sensitive.
                checkFailure = unfinished.getClass().getSimpleName();
            }
            checkDelegatorAuthority(mi, authentication);
            if (llmAnalysisAllowed) {
                enforcePromptQualityCertificateGate(mi, authentication, protectable);
            }

            boolean decideInPlace = isSyncProtectable(protectable);
            if (llmAnalysisAllowed && !decideInPlace) {
                // A stored BLOCK, CHALLENGE or ESCALATE restricts every request of the user; an asynchronous method
                // does not wait for a new decision, so the one in force is enforced before it runs. A person's call
                // whose session, address or browser changed does wait: the gate holds it and answers with its verdict.
                SynchronousProtectableDecisionService.AsyncProtectableGate gate = asyncGate(mi, authentication);
                ZeroTrustAction restriction = gate.restriction();
                if (restriction != null) {
                    if (isEnforcementDisabled()) {
                        log.info("[ZeroTrust][SHADOW] stored decision observed for async Protectable but not enforced. resource={}, action={}",
                                buildResourceId(mi, protectable), restriction);
                    } else {
                        publishEvent = false;
                        throw toZeroTrustAccessDeniedException(restriction, buildResourceId(mi, protectable));
                    }
                } else if (gate.passed()) {
                    // RL-12: one of the few reads of a resource the host declared non-sensitive that pass while the
                    // first is decided. The first publishes its event, which is the analysis that decides; the others
                    // are recorded by the gate and publish nothing, so one question is asked once.
                    publishEvent = gate.publishesEvent();
                } else if (gate.decideInPlace()) {
                    // A1-5: an agent request with no decision on record is not let through; it is decided here as a
                    // synchronous method's request is. One already being analysed for the same session waits.
                    if (rapidReentryAllowed) {
                        decideInPlace = true;
                    } else if (!isEnforcementDisabled()) {
                        throw ZeroTrustAccessDeniedException.analysisRequired(actorSessionDecisionScopeId());
                    }
                }
            }

            if (llmAnalysisAllowed && rapidReentryAllowed && decideInPlace) {
                SynchronousProtectableDecisionService.SyncDecisionResult syncDecision;
                try {
                    syncDecision = evaluateSynchronousProtectable(mi, authentication);
                } catch (RuntimeException syncEvaluationFailure) {
                    if (!isEnforcementDisabled()) {
                        if (!StoreFailures.isStoreFailure(syncEvaluationFailure)) {
                            throw syncEvaluationFailure;
                        }
                        refuseSensitiveCallWithoutItsPolicies(mi, authentication, protectable, checkFailure, publishEvent);
                        contexaStores.passedWithoutDecision();
                        granted = true;
                        invoked = true;
                        return proceed(mi);
                    }
                    log.error("[ZeroTrust][SHADOW] sync Protectable evaluation failed and was not enforced. Access will proceed. resource={}",
                            buildResourceId(mi, protectable), syncEvaluationFailure);
                    publishEvent = false;
                    granted = true;
                    invoked = true;
                    return proceed(mi);
                }
                if (syncDecision.action() != ZeroTrustAction.ALLOW) {
                    if (isEnforcementDisabled()) {
                        log.info("[ZeroTrust][SHADOW] sync Protectable decision observed but not enforced. resource={}, action={}",
                                buildResourceId(mi, protectable), syncDecision.action());
                        publishEvent = false;
                    } else {
                        publishEvent = false;
                        throw toZeroTrustAccessDeniedException(syncDecision, buildResourceId(mi, protectable));
                    }
                } else {
                    publishEvent = false;
                }
            }

            if (llmAnalysisAllowed) {
                refuseSensitiveCallWithoutItsPolicies(mi, authentication, protectable, checkFailure, publishEvent);
            }
            if (llmAnalysisAllowed && (checkFailure != null || contexaStores.anyDown())) {
                contexaStores.passedWithoutDecision();
            }
            granted = true;
            invoked = true;
            return proceed(mi);

        } catch (AuthorizationDeniedException denied) {
            granted = false;
            publishEvent = false;
            denialReason = denied.getMessage();
            if (denied instanceof RapidProtectableReentryDeniedException || denied instanceof ZeroTrustAccessDeniedException) {
                publishEvent = false;
                throw denied;
            }
            if (llmAnalysisAllowed && authorizationDenialRecorder != null) {
                // A real refusal is not analysed, but it is a fact of the session and of the user's scope.
                authorizationDenialRecorder.record(mi, authentication, denialReason);
            }
            if (!invoked) {
                // The method policies or the delegator's authority refused the call before the method ran; a refusal
                // from inside the method is the application's own.
                ProtectableRefusalFilter.markRefusal(currentRequest(), denied);
            }
            return handle(mi, denied);

        } catch (Exception e) {
            if (invoked) {
                // The method ran and threw: authorization let it run, so this is a business failure, not a denial.
                executionFailure = e.getClass().getSimpleName();
            } else {
                // No check said no: a failure of the check is no refusal, and it is not recorded as one (PR-55).
                granted = false;
                denialReason = e.getMessage();
                checkFailure = e.getClass().getSimpleName();
                if (e instanceof AuthenticationException missingUser) {
                    // A method policy needs a user the call does not have: the call is refused for it, as Spring
                    // Security's translation answers such an exception on a path a chain covers.
                    ProtectableRefusalFilter.markRefusal(currentRequest(), missingUser);
                }
            }
            throw e;

        } finally {
            try {
                if (publishEvent && llmAnalysisAllowed) {
                    String executionOutcome = invoked
                            ? (executionFailure != null ? ZeroTrustEventPublisher.METHOD_FAILED : ZeroTrustEventPublisher.METHOD_COMPLETED)
                            : null;
                    publishAuthorizationEvent(mi, authentication, granted, denialReason, executionOutcome, executionFailure,
                            checkFailure);
                }
            } finally {
                RequestPathScope.leave();
            }
        }
    }

    /**
     * The method policies were not read, so a DENY among them is not known, and no decision of the model speaks for
     * a policy. A sensitive resource does not go on then, as it does not without a decision while the analysis is behind.
     * The refusal is this request's, nothing is stored, and a restriction in force has answered before it. A
     * general resource goes on, as the operating mode specifies: stopping every call would turn the outage into one of
     * the application.
     *
     * @param publish whether the call still has to tell the analysis of itself
     */
    private void refuseSensitiveCallWithoutItsPolicies(MethodInvocation mi, Authentication authentication,
                                                       Protectable protectable, String checkFailure, boolean publish) {
        if (checkFailure == null || isEnforcementDisabled() || !sensitive(mi, authentication, protectable)) {
            return;
        }
        String resourceId = buildResourceId(mi, protectable);
        log.warn("[ZeroTrust] Refusing a sensitive Protectable resource: its method policies could not be read. resource={}",
                resourceId);
        if (publish) {
            publishAuthorizationEvent(mi, authentication, false, null, ZeroTrustEventPublisher.METHOD_NOT_RUN, null,
                    checkFailure);
        }
        throw ZeroTrustAccessDeniedException.challengeRequired(resourceId);
    }

    /** Whether the call is for a sensitive resource; what the method declares answers when its facts cannot be read. */
    private boolean sensitive(MethodInvocation mi, Authentication authentication, Protectable protectable) {
        if (synchronousProtectableDecisionService != null) {
            try {
                return synchronousProtectableDecisionService.sensitive(mi, authentication);
            } catch (RuntimeException unread) {
                if (!StoreFailures.isStoreFailure(unread)) {
                    throw unread;
                }
            }
        }
        return protectable != null && ResourceImportanceResolver.resolve(protectable.importance(), protectable.sensitivity())
                == ResourceImportance.SENSITIVE;
    }

    /** The method is the application's: what it does with its time is not bounded as Contexa's own work is. */
    private Object proceed(MethodInvocation mi) throws Throwable {
        int contexaWork = RequestPathScope.suspend();
        try {
            return mi.proceed();
        } catch (AuthorizationDeniedException ex) {
            if (authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
                return handler.handleDeniedInvocation(mi, ex);
            }
            return defaultHandler.handleDeniedInvocation(mi, ex);
        } finally {
            RequestPathScope.resume(contexaWork);
        }
    }

    private Object handle(MethodInvocation mi, AuthorizationDeniedException denied) {
        if (authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
            return handler.handleDeniedInvocation(mi, denied);
        }
        return defaultHandler.handleDeniedInvocation(mi, denied);
    }

    /**
     * Q-10: a scheduled or asynchronous call on a thread that holds neither a user nor a request is no one's request, so
     * there is nothing to decide. A request with no user, and an anonymous visitor's context, which names a known nobody,
     * go to {@link #getAuthentication()}; a user carried into the thread is decided as in a request.
     */
    private boolean hasNoUserToDecide() {
        return this.securityContextHolderStrategy.get().getContext().getAuthentication() == null && currentRequest() == null;
    }

    /** A record that fails stays a logged failure: it must not stop the application's job. */
    private void recordRanWithoutUser(MethodInvocation mi) {
        if (protectableLlmSuppressionWriter == null || !isLlmAnalysisAllowed()) {
            return;
        }
        try {
            protectableLlmSuppressionWriter.recordRanWithoutUser(mi, securityZeroTrustMode());
        } catch (RuntimeException e) {
            log.error("Failed to record a protected method that ran with no user: {}", buildResourceId(mi), e);
        }
    }

    /**
     * The user the call is decided for. A mode that decides on users (SHADOW, ENFORCE) refuses a call without one, as
     * before: with an access denial that carries the missing authentication, so that an application's own exception
     * handling answers it as the denial it is, not as an unknown failure. A mode that decides on nobody (OBSERVE,
     * DISABLED) leaves the call as the application made it: it goes on as a signed-in user's call does there, and the
     * method policies decide on what the context holds, a visitor or nobody.
     */
    private Authentication getAuthentication() {
        Authentication authentication = this.securityContextHolderStrategy.get().getContext().getAuthentication();
        boolean isAnonymous = this.authenticationTrustResolver.isAnonymous(authentication);
        if ((authentication == null || isAnonymous) && isLlmAnalysisAllowed()) {
            throw ProtectableRefusalFilter.markRefusal(currentRequest(), ProtectableRefusalFilter.withoutUser(
                    "Authentication is anonymousUser or was not found in the SecurityContext"));
        }
        return authentication;
    }

    private Protectable resolveProtectable(MethodInvocation mi) {
        Protectable protectable = AnnotationUtils.findAnnotation(mi.getMethod(), Protectable.class);
        if (protectable != null) {
            return protectable;
        }

        Object target = mi.getThis();
        if (target != null) {
            Class<?> targetClass = AopProxyUtils.ultimateTargetClass(target);
            Method specificMethod = AopUtils.getMostSpecificMethod(mi.getMethod(), targetClass);
            protectable = AnnotationUtils.findAnnotation(specificMethod, Protectable.class);
            if (protectable != null) {
                return protectable;
            }
            protectable = AnnotationUtils.findAnnotation(targetClass, Protectable.class);
            if (protectable != null) {
                return protectable;
            }
        }

        return AnnotationUtils.findAnnotation(mi.getMethod().getDeclaringClass(), Protectable.class);
    }

    private boolean isSyncProtectable(Protectable protectable) {
        return protectable != null && protectable.sync();
    }

    private void enforcePromptQualityCertificateGate(
            MethodInvocation mi,
            Authentication authentication,
            Protectable protectable) {
        if (protectable == null || !protectable.verificationRequired() || protectableResourceCertificationGate == null) {
            return;
        }
        String resourceId = buildResourceId(mi, protectable);
        ProtectableResourceCertificationGate.CertificationDecision decision =
                protectableResourceCertificationGate.evaluate(mi, authentication, protectable, resourceId);
        if (decision == null || decision.allowed()) {
            return;
        }
        if (isEnforcementDisabled()) {
            log.info("[ZeroTrust][SHADOW] Protectable resource is not prompt-quality certified. resource={}, state={}, message={}",
                    resourceId,
                    decision.state(),
                    decision.message());
            return;
        }
        log.warn("[ZeroTrust] Blocking uncertified Protectable resource. resource={}, state={}, message={}",
                resourceId,
                decision.state(),
                decision.message());
        throw ZeroTrustAccessDeniedException.pendingReview(resourceId);
    }

    private SynchronousProtectableDecisionService.SyncDecisionResult evaluateSynchronousProtectable(
            MethodInvocation mi,
            Authentication authentication) {
        if (synchronousProtectableDecisionService == null) {
            throw ZeroTrustAccessDeniedException.analysisRequired(buildResourceId(mi, resolveProtectable(mi)));
        }
        return synchronousProtectableDecisionService.analyze(mi, authentication);
    }

    private SynchronousProtectableDecisionService.AsyncProtectableGate asyncGate(MethodInvocation mi,
                                                                                 Authentication authentication) {
        if (synchronousProtectableDecisionService == null || authentication == null) {
            return SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED;
        }
        try {
            SynchronousProtectableDecisionService.AsyncProtectableGate gate =
                    synchronousProtectableDecisionService.asyncGate(mi, authentication);
            return gate != null ? gate : SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED;
        } catch (RuntimeException unfinished) {
            // The stored restrictions answer from what the repository keeps; a gate a store ended found none of them.
            if (!StoreFailures.isStoreFailure(unfinished)) {
                throw unfinished;
            }
            return SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED;
        }
    }

    private ZeroTrustAccessDeniedException toZeroTrustAccessDeniedException(
            SynchronousProtectableDecisionService.SyncDecisionResult decision,
            String resourceId) {
        return toZeroTrustAccessDeniedException(decision.action(), resourceId);
    }

    private ZeroTrustAccessDeniedException toZeroTrustAccessDeniedException(ZeroTrustAction decided, String resourceId) {
        ZeroTrustAction action = decided != null ? decided : ZeroTrustAction.PENDING_ANALYSIS;

        return switch (action) {
            case BLOCK -> ZeroTrustAccessDeniedException.blocked(resourceId);
            case CHALLENGE -> ZeroTrustAccessDeniedException.challengeRequired(resourceId);
            case ESCALATE -> ZeroTrustAccessDeniedException.pendingReview(resourceId);
            case PENDING_ANALYSIS -> ZeroTrustAccessDeniedException.analysisRequired(resourceId);
            case ALLOW -> ZeroTrustAccessDeniedException.analysisRequired(resourceId);
        };
    }

    private String buildResourceId(MethodInvocation mi) {
        return buildResourceId(mi, resolveProtectable(mi));
    }

    private String buildResourceId(MethodInvocation mi, Protectable protectable) {
        return mi.getMethod().getDeclaringClass().getSimpleName() + "." + mi.getMethod().getName();
    }

    private String actorSessionDecisionScopeId() {
        return "ACTOR_SESSION_CONTEXT";
    }

    @Override
    public Pointcut getPointcut() { return this.pointcut; }
    @Override
    public Advice getAdvice() { return this; }
    @Override
    public boolean isPerInstance() { return true; }
    @Override
    public int getOrder() { return this.order; }

    public void setAuthorizationManager(ProtectableMethodAuthorizationManager authorizationManager) {
        this.authorizationManager = authorizationManager;
    }

    public void setRapidReentryGuard(ProtectableRapidReentryGuard rapidReentryGuard) {
        this.rapidReentryGuard = rapidReentryGuard;
    }

    public void setZeroTrustEventPublisher(ZeroTrustEventPublisher zeroTrustEventPublisher) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
    }

    public void setMetricsCollector(AuthorizationMetrics metricsCollector) {
        this.metricsCollector = metricsCollector;
    }

    public void setSynchronousProtectableDecisionService(
            SynchronousProtectableDecisionService synchronousProtectableDecisionService) {
        this.synchronousProtectableDecisionService = synchronousProtectableDecisionService;
    }

    public void setProtectableResourceCertificationGate(
            ProtectableResourceCertificationGate protectableResourceCertificationGate) {
        this.protectableResourceCertificationGate = protectableResourceCertificationGate;
    }

    public void setSecurityZeroTrustProperties(SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    public void setProtectableLlmSuppressionWriter(ProtectableLlmSuppressionWriter protectableLlmSuppressionWriter) {
        this.protectableLlmSuppressionWriter = protectableLlmSuppressionWriter;
    }

    /** A1-8: checks a delegated agent's call against the authority of the person it acts for. */
    public void setDelegatorAuthority(DelegatorAuthority delegatorAuthority) {
        this.delegatorAuthority = delegatorAuthority;
    }

    /**
     * A1-8: a delegated agent's call the method policies grant is evaluated again as the person the agent acts for and
     * refused, before any Contexa decision, when that person could not make it (in SHADOW mode it is only recorded).
     */
    private void checkDelegatorAuthority(MethodInvocation mi, Authentication authentication) {
        if (delegatorAuthority == null) {
            return;
        }
        HttpServletRequest request = currentRequest();
        DelegatorAuthority.Check check = delegatorAuthority.prepare(request, authentication).orElse(null);
        if (check == null) {
            return;
        }
        DelegatorAuthority.Outcome outcome = check.outcome();
        if (check.delegator() != null) {
            try {
                authorizationManager.protectable(check::delegator, mi);
                outcome = DelegatorAuthority.Outcome.PERMITTED;
            } catch (AuthorizationDeniedException deniedToTheDelegator) {
                outcome = DelegatorAuthority.Outcome.DENIED;
            }
        }
        DelegatorAuthority.record(request, outcome);
        if (!DelegatorAuthority.refuses(outcome)) {
            return;
        }
        if (isEnforcementDisabled()) {
            log.info("[ZeroTrust][SHADOW] the delegator {} may not make this call; recorded, not enforced: {}",
                    check.delegatorId(), mi.getMethod());
            return;
        }
        throw new AuthorizationDeniedException("Access is denied - the delegator " + check.delegatorId()
                + " may not make this call (" + outcome + ")");
    }

    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest()
                : null;
    }

    public void setAuthorizationDenialRecorder(AuthorizationDenialRecorder authorizationDenialRecorder) {
        this.authorizationDenialRecorder = authorizationDenialRecorder;
    }

    /** The stores a decision needs, and the record of the calls that went on without one (Q-7). */
    public void setContexaStores(ContexaStores contexaStores) {
        this.contexaStores = contexaStores;
    }

    private void recordSuppressedProtectable(Authentication authentication, MethodInvocation mi, String reason) {
        if (protectableLlmSuppressionWriter == null) {
            return;
        }
        protectableLlmSuppressionWriter.recordSuppressed(authentication, mi, reason, securityZeroTrustMode());
    }

    private boolean isEnforcementDisabled() {
        return securityZeroTrustProperties != null && !securityZeroTrustProperties.isEnforcementEnabled();
    }

    private boolean isLlmAnalysisAllowed() {
        return securityZeroTrustProperties == null || securityZeroTrustProperties.allowsLlmAnalysis();
    }

    private String securityZeroTrustMode() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getMode() == null) {
            return "UNSPECIFIED";
        }
        return securityZeroTrustProperties.getMode().name();
    }

    private void publishAuthorizationEvent(MethodInvocation mi, Authentication authentication,
                                           boolean granted, String denialReason,
                                           String executionOutcome, String executionFailure, String checkFailure) {
        if (zeroTrustEventPublisher == null) {
            return;
        }

        try {
            long startTime = System.nanoTime();

            if (checkFailure != null) {
                zeroTrustEventPublisher.publishUncheckedMethodAuthorization(
                    mi,
                    authentication,
                    checkFailure,
                    executionOutcome,
                    executionFailure
                );
            } else {
                zeroTrustEventPublisher.publishMethodAuthorization(
                    mi,
                    authentication,
                    granted,
                    denialReason,
                    executionOutcome,
                    executionFailure
                );
            }

            long duration = System.nanoTime() - startTime;

            if (metricsCollector != null) {
                metricsCollector.recordProtectable(duration);
                metricsCollector.recordAuthzDecision();
            }

        } catch (Exception e) {
            log.error("Failed to publish authorization event", e);
        }
    }
}
