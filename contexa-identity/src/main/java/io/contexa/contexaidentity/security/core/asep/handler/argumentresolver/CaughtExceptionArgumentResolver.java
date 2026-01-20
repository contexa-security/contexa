package io.contexa.contexaidentity.security.core.asep.handler.argumentresolver;

import io.contexa.contexaidentity.security.core.asep.annotation.CaughtException;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

@Slf4j
@Order(Ordered.LOWEST_PRECEDENCE) 
public class CaughtExceptionArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        
        return parameter.hasParameterAnnotation(CaughtException.class) &&
                Throwable.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException, 
                                  HandlerMethod handlerMethod) throws Exception {

        if (caughtException == null) { 
            log.trace("ASEP: CaughtException is null, cannot resolve @CaughtException parameter.");
            return null;
        }

        
        if (parameter.getParameterType().isInstance(caughtException)) {
            log.debug("ASEP: Resolving @CaughtException parameter with the primary caught exception: {}", caughtException.getClass().getSimpleName());
            return caughtException;
        }
        
        
        

        log.warn("ASEP: @CaughtException annotated parameter type [{}] is not directly assignable from the primary caught exception type [{}]. Returning null.",
                parameter.getParameterType().getName(), caughtException.getClass().getName());
        return null; 
    }
}
