package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Order // 가장 마지막에 실행되도록 Order 설정
public class WebSpelExpressionEvaluator implements ExpressionEvaluator {

    @Override
    public boolean supports(String expression) {
        // 다른 평가기에서 처리하지 못한 모든 표현식을 지원 (Fallback 역할)
        return true;
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        // 이제 이 클래스는 manager를 직접 생성하지 않습니다.
        // Resolver가 이 클래스가 supports() == true 임을 확인하고,
        // 직접 WebExpressionAuthorizationManager를 생성하여 핸들러를 주입합니다.
        // 따라서 이 메서드가 직접 호출될 일은 없지만, 인터페이스 구현을 위해 남겨둡니다.
        // 만약 호출된다면, 커스텀 핸들러가 적용되지 않은 기본 manager가 생성됩니다.
        return new WebExpressionAuthorizationManager(expression);
    }
}