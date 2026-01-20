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
    private final int order = AuthorizationInterceptorsOrder.FIRST.getOrder() + 1; // 다른 인터셉터보다 약간 뒤에 실행
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
            // Pre-authorization
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
            // @Protectable 메서드는 항상 이벤트 발행 (민감한 리소스)
            publishAuthorizationEvent(mi, authentication, granted, denialReason);
        }
    }

    /**
     * 메서드 실행을 진행하고, 실행 중 발생하는 AuthorizationDeniedException을 처리한다.
     * Spring Security의 AuthorizationManagerBeforeMethodInterceptor와 동일한 패턴 적용.
     */
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

    /**
     * 권한 거부 시 핸들러에게 처리를 위임한다.
     * authorizationManager가 MethodAuthorizationDeniedHandler를 구현하면 해당 핸들러 사용,
     * 그렇지 않으면 기본 ThrowingMethodAuthorizationDeniedHandler 사용.
     */
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
    
    /**
     * @Protectable 메서드 접근에 대한 이벤트 발행
     * Zero Trust 아키텍처의 핵심 - 모든 민감한 메서드 접근을 추적
     *
     * AI Native v13.0: ZeroTrustEventPublisher 사용
     */
    private void publishAuthorizationEvent(MethodInvocation mi, Authentication authentication,
                                          boolean granted, String denialReason) {
        if (zeroTrustEventPublisher == null) {
            return;
        }

        try {
            // ===== 메트릭 수집 =====
            long startTime = System.nanoTime();

            // AI Native v13.0: ZeroTrustEventPublisher 사용
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