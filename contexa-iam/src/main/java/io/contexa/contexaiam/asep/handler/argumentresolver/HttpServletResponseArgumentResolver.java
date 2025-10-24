package io.contexa.contexaiam.asep.handler.argumentresolver;

import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public class HttpServletResponseArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return HttpServletResponse.class.isAssignableFrom(parameter.getParameterType()) ||
                ServletResponse.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {
        return response;
    }
}
