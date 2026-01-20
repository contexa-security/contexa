package io.contexa.contexaiam.security.xacml.pep;

import lombok.extern.slf4j.Slf4j;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.EventPublishingMetrics;

import java.util.function.Supplier;

@Slf4j
public class AuthorizationManagerMethodInterceptor implements MethodInterceptor, AuthorizationAdvisor {

    private final Pointcut pointcut;
    private final ProtectableMethodAuthorizationManager authorizationManager;
    private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();
    private final int order = AuthorizationInterceptorsOrder.FIRST.getOrder() + 1; 
    private final Supplier<SecurityContextHolderStrategy> securityContextHolderStrategy = SecurityContextHolder::getContextHolderStrategy;
    private ZeroTrustEventPublisher zeroTrustEventPublisher;
    private EventPublishingMetrics metricsCollector;

    public AuthorizationManagerMethodInterceptor(Pointcut pointcut, ProtectableMethodAuthorizationManager authorizationManager) {
        this.pointcut = pointcut;
        this.authorizationManager = authorizationManager;
    }

    @Override
    public Object invoke(MethodInvocation mi) throws Throwable {
        Authentication authentication = getAuthentication();
        boolean granted = false;
        String denialReason = null;

        try {
            
            authorizationManager.protectable(() -> authentication, mi);
            granted = true;
            return proceed(mi);

        } catch (AuthorizationDeniedException denied) {
            granted = false;
            denialReason = denied.getMessage();
            return handle(mi, denied);

        } catch (Exception e) {
            granted = false;
            denialReason = e.getMessage();
            throw e;

        } finally {
            
            publishAuthorizationEvent(mi, authentication, granted, denialReason);
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

    public void setMetricsCollector(EventPublishingMetrics metricsCollector) {
        this.metricsCollector = metricsCollector;
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

            String resource = mi.getMethod().getDeclaringClass().getSimpleName() + "." + mi.getMethod().getName();
            log.debug("Published authorization event for @Protectable method: {} - granted: {}",
                     resource, granted);

        } catch (Exception e) {
            log.error("Failed to publish authorization event", e);
        }
    }
}