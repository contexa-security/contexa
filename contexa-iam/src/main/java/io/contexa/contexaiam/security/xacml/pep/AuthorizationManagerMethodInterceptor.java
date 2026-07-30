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

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import java.lang.reflect.Method;
import java.util.function.Supplier;

@Slf4j
public class AuthorizationManagerMethodInterceptor implements MethodInterceptor, AuthorizationAdvisor {

    private final Pointcut pointcut;
    private final ProtectableMethodAuthorizationManager authorizationManager;
    private final ProtectableRapidReentryGuard rapidReentryGuard;
    private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();
    private final int order = AuthorizationInterceptorsOrder.FIRST.getOrder() + 1;
    private final Supplier<SecurityContextHolderStrategy> securityContextHolderStrategy = SecurityContextHolder::getContextHolderStrategy;
    private ZeroTrustEventPublisher zeroTrustEventPublisher;
    private AuthorizationMetrics metricsCollector;
    private SynchronousProtectableDecisionService synchronousProtectableDecisionService;
    private SecurityZeroTrustProperties securityZeroTrustProperties;
    private ProtectableResourceCertificationGate protectableResourceCertificationGate;
    private ProtectableLlmSuppressionWriter protectableLlmSuppressionWriter;
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    public AuthorizationManagerMethodInterceptor(
            Pointcut pointcut,
            ProtectableMethodAuthorizationManager authorizationManager,
            ProtectableRapidReentryGuard rapidReentryGuard) {
        this.pointcut = pointcut;
        this.authorizationManager = authorizationManager;
        this.rapidReentryGuard = rapidReentryGuard;
    }

    @Override
    public Object invoke(MethodInvocation mi) throws Throwable {
        Authentication authentication = getAuthentication();
        boolean granted = false;
        boolean publishEvent = true;
        String denialReason = null;
        Protectable protectable = resolveProtectable(mi);
        boolean llmAnalysisAllowed = isLlmAnalysisAllowed();
        boolean rapidReentryAllowed = true;

        try {
            if (!llmAnalysisAllowed) {
                publishEvent = false;
                log.debug("[ZeroTrust] AI decision analysis is disabled for Protectable invocation. mode={}",
                        securityZeroTrustMode());
            } else {
                rapidReentryAllowed = rapidReentryGuard.tryAcquire(authentication, mi);
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

            authorizationManager.protectable(() -> authentication, mi);
            if (llmAnalysisAllowed) {
                enforcePromptQualityCertificateGate(mi, authentication, protectable);
            }

            if (llmAnalysisAllowed && rapidReentryAllowed && isSyncProtectable(protectable)) {
                SynchronousProtectableDecisionService.SyncDecisionResult syncDecision = evaluateSynchronousProtectable(mi, authentication);
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

            granted = true;
            return proceed(mi);

        } catch (AuthorizationDeniedException denied) {
            granted = false;
            publishEvent = false;
            denialReason = denied.getMessage();
            if (denied instanceof RapidProtectableReentryDeniedException || denied instanceof ZeroTrustAccessDeniedException) {
                publishEvent = false;
                throw denied;
            }
            return handle(mi, denied);

        } catch (Exception e) {
            granted = false;
            denialReason = e.getMessage();
            throw e;

        } finally {
            if (publishEvent && llmAnalysisAllowed) {
                publishAuthorizationEvent(mi, authentication, granted, denialReason);
            }
        }
    }

    private Object proceed(MethodInvocation mi) throws Throwable {
        try {
            return mi.proceed();
        } catch (AuthorizationDeniedException ex) {
            if (authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
                return handler.handleDeniedInvocation(mi, ex);
            }
            return defaultHandler.handleDeniedInvocation(mi, ex);
        }
    }

    private Object handle(MethodInvocation mi, AuthorizationDeniedException denied) {
        if (authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
            return handler.handleDeniedInvocation(mi, denied);
        }
        return defaultHandler.handleDeniedInvocation(mi, denied);
    }

    private Authentication getAuthentication() {
        Authentication authentication = this.securityContextHolderStrategy.get().getContext().getAuthentication();
        boolean isAnonymous = this.authenticationTrustResolver.isAnonymous(authentication);
        if (authentication == null || isAnonymous) {
            throw new AuthenticationCredentialsNotFoundException("Authentication is anonymousUser or was not found in the SecurityContext");
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

    private ZeroTrustAccessDeniedException toZeroTrustAccessDeniedException(
            SynchronousProtectableDecisionService.SyncDecisionResult decision,
            String resourceId) {
        ZeroTrustAction action = decision.action() != null ? decision.action() : ZeroTrustAction.PENDING_ANALYSIS;

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
                                           boolean granted, String denialReason) {
        if (zeroTrustEventPublisher == null) {
            return;
        }

        try {
            long startTime = System.nanoTime();

            zeroTrustEventPublisher.publishMethodAuthorization(
                mi,
                authentication,
                granted,
                denialReason
            );

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
