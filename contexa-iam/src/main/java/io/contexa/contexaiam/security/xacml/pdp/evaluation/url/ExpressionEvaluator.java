package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * 특정 인가 표현식을 지원하고, 그에 맞는 Spring Security의 AuthorizationManager를 생성하는 전략 인터페이스.
 */
public interface ExpressionEvaluator {
    /**
     * 주어진 표현식을 이 평가기가 처리할 수 있는지 확인합니다.
     * @param expression 인가 표현식 (예: "hasAuthority('ROLE_USER')")
     * @return 지원 여부
     */
    boolean supports(String expression);

    /**
     * 지원하는 표현식을 기반으로 실제 Spring Security의 AuthorizationManager 인스턴스를 생성합니다.
     * @param expression 인가 표현식
     * @return 생성된 AuthorizationManager
     */
    AuthorizationManager<RequestAuthorizationContext> createManager(String expression);
}