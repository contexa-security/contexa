package io.contexa.contexaiam.asep.handler.returnvaluehandler;

import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public interface SecurityHandlerMethodReturnValueHandler {
    boolean supportsReturnType(MethodParameter returnType);

    void handleReturnValue(@Nullable Object returnValue,
                           MethodParameter returnType,
                           HttpServletRequest request,
                           HttpServletResponse response,
                           @Nullable Authentication authentication,
                           HandlerMethod handlerMethod,
                           @Nullable MediaType resolvedMediaType) throws Exception;
}
