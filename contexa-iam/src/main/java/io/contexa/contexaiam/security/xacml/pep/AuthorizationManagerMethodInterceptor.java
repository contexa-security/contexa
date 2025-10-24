package io.contexa.contexaiam.security.xacml.pep;

import lombok.extern.slf4j.Slf4j;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import io.contexa.contexacore.autonomous.event.publisher.AuthorizationEventPublisher;

import java.util.function.Supplier;

@Slf4j
public class AuthorizationManagerMethodInterceptor implements MethodInterceptor, AuthorizationAdvisor {

    private final Pointcut pointcut;
    private final ProtectableMethodAuthorizationManager authorizationManager;
    private int order = AuthorizationInterceptorsOrder.FIRST.getOrder() + 1; // 다른 인터셉터보다 약간 뒤에 실행
    private final Supplier<SecurityContextHolderStrategy> securityContextHolderStrategy = SecurityContextHolder::getContextHolderStrategy;
    private AuthorizationEventPublisher authorizationEventPublisher;

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
            authorizationManager.preAuthorize(() -> authentication, mi);
            granted = true;
            
            // Method execution
            Object returnObject = mi.proceed();
            
            // Post-authorization
            authorizationManager.postAuthorize(() -> authentication, mi, returnObject);
            
            return returnObject;
            
        } catch (Exception e) {
            granted = false;
            denialReason = e.getMessage();
            throw e;
            
        } finally {
            // @Protectable 메서드는 항상 이벤트 발행 (민감한 리소스)
            publishAuthorizationEvent(mi, authentication, granted, denialReason);
        }
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
    
    public void setAuthorizationEventPublisher(AuthorizationEventPublisher authorizationEventPublisher) {
        this.authorizationEventPublisher = authorizationEventPublisher;
    }
    
    /**
     * @Protectable 메서드 접근에 대한 이벤트 발행
     * Zero Trust 아키텍처의 핵심 - 모든 민감한 메서드 접근을 추적
     */
    private void publishAuthorizationEvent(MethodInvocation mi, Authentication authentication, 
                                          boolean granted, String denialReason) {
        if (authorizationEventPublisher == null) {
            return;
        }
        
        try {
            // 통합된 AuthorizationEventPublisher 사용 - 올바른 시그니처 사용
            authorizationEventPublisher.publishMethodAuthorizationDecisionAsync(
                mi,
                authentication,
                granted,
                denialReason
            );
            
            String resource = mi.getMethod().getDeclaringClass().getSimpleName() + "." + mi.getMethod().getName();
            log.debug("Published authorization event for @Protectable method: {} - granted: {}", 
                     resource, granted);
                     
        } catch (Exception e) {
            log.error("Failed to publish authorization event", e);
        }
    }
}