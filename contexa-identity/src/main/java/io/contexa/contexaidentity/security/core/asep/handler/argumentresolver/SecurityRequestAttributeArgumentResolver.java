package io.contexa.contexaidentity.security.core.asep.handler.argumentresolver;

import io.contexa.contexaidentity.security.core.asep.annotation.SecurityRequestAttribute;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public class SecurityRequestAttributeArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecurityRequestAttribute.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {

        SecurityRequestAttribute annotation = parameter.getParameterAnnotation(SecurityRequestAttribute.class);
        if (annotation == null) { return null; }

        String attributeName = annotation.name();
        if (!StringUtils.hasText(attributeName)) {
            attributeName = parameter.getParameterName();
            if (attributeName == null) {
                throw new IllegalArgumentException("Request attribute name for argument type [" + parameter.getParameterType().getName() +
                        "] not specified, and parameter name information not available.");
            }
        }

        Object attributeValue = request.getAttribute(attributeName);

        if (attributeValue == null) {
            if (annotation.required()) {
                throw new MissingRequestAttributeException(attributeName, parameter);
            }
            return null;
        }

        if (parameter.getParameterType().isInstance(attributeValue)) {
            return attributeValue;
        }
        throw new IllegalArgumentException("Request attribute '" + attributeName + "' is of type [" + attributeValue.getClass().getName() +
                "] but method parameter type is [" + parameter.getParameterType().getName() + "]");
    }

    public static class MissingRequestAttributeException extends RuntimeException {
        private final String attributeName;
        private final MethodParameter parameter;
        public MissingRequestAttributeException(String attributeName, MethodParameter parameter) {
            super("Required request attribute '" + attributeName + "' for method parameter type " +
                    parameter.getParameterType().getName() + " is not present");
            this.attributeName = attributeName;
            this.parameter = parameter;
        }
        public String getAttributeName() { return this.attributeName; }
        public MethodParameter getMethodParameter() { return this.parameter; }
    }
}
