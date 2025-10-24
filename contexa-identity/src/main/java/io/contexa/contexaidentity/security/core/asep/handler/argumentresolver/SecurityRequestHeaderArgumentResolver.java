package io.contexa.contexaidentity.security.core.asep.handler.argumentresolver;

import io.contexa.contexaidentity.security.core.asep.annotation.SecurityRequestHeader;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ValueConstants;

import java.util.Objects;

@Slf4j
public final class SecurityRequestHeaderArgumentResolver implements SecurityHandlerMethodArgumentResolver {
    private final ConversionService conversionService;

    public SecurityRequestHeaderArgumentResolver(ConversionService conversionService) {
        this.conversionService = Objects.requireNonNull(conversionService, "ConversionService must not be null");
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecurityRequestHeader.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter, HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, @Nullable Throwable caughtException, HandlerMethod handlerMethod) {
        SecurityRequestHeader annotation = parameter.getParameterAnnotation(SecurityRequestHeader.class);
        Assert.state(annotation != null, "No SecurityRequestHeader annotation");

        String headerName = StringUtils.hasText(annotation.name()) ? annotation.name() : parameter.getParameterName();
        if (headerName == null) {
            throw new IllegalArgumentException("Request header name for argument type [" +
                    parameter.getParameterType().getName() + "] not specified and parameter name information not available.");
        }

        String headerValue = request.getHeader(headerName);
        Object resolvedValue = null;

        if (headerValue == null) {
            if (annotation.required()) {
                throw new MissingRequestHeaderException(headerName, parameter);
            }
            String defaultValue = annotation.defaultValue();
            if (!ValueConstants.DEFAULT_NONE.equals(defaultValue)) {
                resolvedValue = convertValue(defaultValue, parameter, "default value");
            }
        } else {
            resolvedValue = convertValue(headerValue, parameter, "header '" + headerName + "'");
        }
        return resolvedValue;
    }

    @Nullable
    private Object convertValue(@Nullable String value, MethodParameter parameter, String valueSourceDescription) {
        if (value == null) {
            return null;
        }
        TypeDescriptor sourceType = TypeDescriptor.valueOf(String.class);
        TypeDescriptor targetType = new TypeDescriptor(parameter);

        if (this.conversionService.canConvert(sourceType, targetType)) {
            try {
                return this.conversionService.convert(value, sourceType, targetType);
            } catch (Exception ex) {
                throw new IllegalArgumentException("Failed to convert " + valueSourceDescription +
                        " value [" + value + "] to target type [" + parameter.getParameterType().getName() + "]", ex);
            }
        } else if (String.class.isAssignableFrom(parameter.getParameterType()) && parameter.getParameterType().isInstance(value)) {
            return value;
        }
        throw new IllegalStateException("ASEP: Cannot convert " + valueSourceDescription + " String [" + value +
                "] to target type [" + parameter.getParameterType().getName() + "] for parameter [" +
                parameter.getParameterName() + "]. No suitable converter found.");
    }

    @SuppressWarnings("serial")
    public static final class MissingRequestHeaderException extends RuntimeException {
        private final String headerName;
        private final MethodParameter parameter;

        public MissingRequestHeaderException(String headerName, MethodParameter parameter) {
            super("Required request header '" + headerName + "' for method parameter type " +
                    parameter.getParameterType().getName() + " is not present");
            this.headerName = headerName;
            this.parameter = parameter;
        }
        public String getHeaderName() { return this.headerName; }
        public MethodParameter getMethodParameter() { return this.parameter; }
    }
}
