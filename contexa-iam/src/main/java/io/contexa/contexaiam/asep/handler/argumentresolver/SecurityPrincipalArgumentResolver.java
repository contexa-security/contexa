package io.contexa.contexaiam.asep.handler.argumentresolver;

import io.contexa.contexaiam.asep.annotation.SecurityPrincipal;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public class SecurityPrincipalArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecurityPrincipal.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal != null && parameter.getParameterType().isInstance(principal)) {
            return principal;
        }
        // SpEL 표현식 지원 등은 현재 미구현
        return null;
    }
}
