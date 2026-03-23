package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.exception.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.exception.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
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

        try {
            rapidReentryGuard.check(authentication, mi);
            authorizationManager.protectable(() -> authentication, mi);

            Protectable protectable = resolveProtectable(mi);
            if (isSyncProtectable(protectable)) {
                SynchronousProtectableDecisionService.SyncDecisionResult syncDecision = evaluateSynchronousProtectable(mi, authentication);
                if (syncDecision.action() != ZeroTrustAction.ALLOW) {
                    publishEvent = false;
                    throw toZeroTrustAccessDeniedException(syncDecision, buildResourceId(mi));
                }
                publishEvent = false;
            }

            granted = true;
            return proceed(mi);

        } catch (AuthorizationDeniedException denied) {
            granted = false;
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
            if (publishEvent) {
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
        if (authentication == null) {
            throw new AuthenticationCredentialsNotFoundException("An Authentication object was not found in the SecurityContext");
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

    private SynchronousProtectableDecisionService.SyncDecisionResult evaluateSynchronousProtectable(
            MethodInvocation mi,
            Authentication authentication) {
        if (synchronousProtectableDecisionService == null) {
            throw ZeroTrustAccessDeniedException.analysisRequired(buildResourceId(mi));
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
        return mi.getMethod().getDeclaringClass().getSimpleName() + "." + mi.getMethod().getName();
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
