package io.contexa.contexaiam.asep.handler.argumentresolver;

import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public class HttpServletRequestArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return HttpServletRequest.class.isAssignableFrom(parameter.getParameterType()) ||
                ServletRequest.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {
        return request;
    }
}
