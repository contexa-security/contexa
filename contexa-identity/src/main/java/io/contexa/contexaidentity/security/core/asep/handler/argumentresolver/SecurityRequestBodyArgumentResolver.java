package io.contexa.contexaidentity.security.core.asep.handler.argumentresolver;

import io.contexa.contexaidentity.security.core.asep.annotation.SecurityRequestBody;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.web.HttpMediaTypeNotSupportedException;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Slf4j
public final class SecurityRequestBodyArgumentResolver implements SecurityHandlerMethodArgumentResolver {
    private final List<HttpMessageConverter<?>> messageConverters;

    public SecurityRequestBodyArgumentResolver(List<HttpMessageConverter<?>> messageConverters) {
        
        this.messageConverters = Collections.unmodifiableList(
                new ArrayList<>(Objects.requireNonNull(messageConverters, "MessageConverters must not be null for SecurityRequestBodyArgumentResolver"))
        );
        if (this.messageConverters.isEmpty()){
            log.warn("ASEP: HttpMessageConverter list is empty for SecurityRequestBodyArgumentResolver. Request body processing will likely fail.");
        }
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecurityRequestBody.class);
    }

    @Override
    @Nullable
    @SuppressWarnings({"rawtypes"}) 
    public Object resolveArgument(MethodParameter parameter, HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, @Nullable Throwable caughtException, HandlerMethod handlerMethod)
            throws IOException, HttpMediaTypeNotSupportedException, HttpMessageNotReadableException {

        SecurityRequestBody requestBodyAnnotation = parameter.getParameterAnnotation(SecurityRequestBody.class);
        Assert.state(requestBodyAnnotation != null, "No SecurityRequestBody annotation. This should have been checked by supportsParameter.");

        HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
        MediaType contentType = inputMessage.getHeaders().getContentType();

        if (contentType == null) {
                    }

        Type targetType = parameter.getGenericParameterType(); 
        Class<?> targetClass = parameter.getParameterType(); 

        Object body = null;
        boolean bodyReadSuccessfully = false;

        if (this.messageConverters.isEmpty() && requestBodyAnnotation.required()) {
            throw new HttpMessageNotReadableException(
                    "ASEP: No HttpMessageConverters configured to read request body for @SecurityRequestBody, and request body is required.", inputMessage);
        }

        for (HttpMessageConverter<?> converter : this.messageConverters) {
            
            if (converter.canRead(targetClass, contentType)) {
                try {
                    
                    body = ((HttpMessageConverter<Object>) converter).read((Class<Object>) targetClass, inputMessage);
                    bodyReadSuccessfully = true;
                    if (log.isDebugEnabled()) {
                                            }
                    break; 
                } catch (IOException | HttpMessageNotReadableException ex) {
                    
                    log.warn("ASEP: Could not read HTTP request body with HttpMessageConverter [{}]: {}",
                            converter.getClass().getSimpleName(), ex.getMessage());

                    if (ex instanceof IOException && !(ex instanceof HttpMessageNotReadableException)) {
                        throw new HttpMessageNotReadableException("IO error while reading request body: " + ex.getMessage(), ex, inputMessage);
                    }
                    
                }
            }
        }

        if (!bodyReadSuccessfully) {
            
            if (contentType != null) { 
                List<MediaType> supportedMediaTypes = this.messageConverters.stream()
                        .filter(c -> c.canRead(targetClass, null)) 
                        
                        .flatMap(c -> c.getSupportedMediaTypes(targetClass).stream())
                        .distinct()
                        .toList();
                throw new HttpMediaTypeNotSupportedException(contentType, supportedMediaTypes);
            } else { 
                
            }
        }

        if (body == null && requestBodyAnnotation.required()) {

            throw new RequestBodyRequiredException(
                    "Request body is required for parameter type " + targetClass.getName() +
                            " but was effectively null or no suitable converter found.", parameter);
        }

        return body;
    }

    public static final class RequestBodyRequiredException extends RuntimeException {
        private final transient MethodParameter parameter; 

        public RequestBodyRequiredException(String message, MethodParameter parameter) {
            super(message);
            this.parameter = parameter;
        }

        public MethodParameter getParameter() { return this.parameter; }
    }
}
