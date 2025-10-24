package io.contexa.contexaiam.security.xacml.pip.context;

import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation; // MethodInvocation 임포트
import org.springframework.security.core.Authentication;

/**
 * 웹 계층의 요청을 인가 엔진이 사용할 표준 컨텍스트로 변환하는 책임.
 */
public interface ContextHandler {
    /**
     * URL 기반 보안(Web Security)을 위한 컨텍스트를 생성합니다.
     */
    AuthorizationContext create(Authentication authentication, HttpServletRequest request);

    /**
     * [신규] 메서드 기반 보안(Method Security)을 위한 컨텍스트를 생성합니다.
     */
    AuthorizationContext create(Authentication authentication, MethodInvocation invocation);

//    AuthorizationContext buildContext(HttpServletRequest request, Object resource);
}
