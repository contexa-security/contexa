package io.contexa.contexaiam.asep.handler.argumentresolver;

import io.contexa.contexaiam.asep.annotation.SecurityRequestBody;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
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
        // 생성자에서부터 null을 허용하지 않고, 불변 리스트로 방어적 복사
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
    @SuppressWarnings({"rawtypes"}) // HttpMessageConverter<Object>로 캐스팅 시 발생하는 경고 억제
    public Object resolveArgument(MethodParameter parameter, HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, @Nullable Throwable caughtException, HandlerMethod handlerMethod)
            throws IOException, HttpMediaTypeNotSupportedException, HttpMessageNotReadableException {

        SecurityRequestBody requestBodyAnnotation = parameter.getParameterAnnotation(SecurityRequestBody.class);
        Assert.state(requestBodyAnnotation != null, "No SecurityRequestBody annotation. This should have been checked by supportsParameter.");

        HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
        MediaType contentType = inputMessage.getHeaders().getContentType();

        if (contentType == null) {
            log.debug("ASEP: Request Content-Type is not specified. HttpMessageConverter will attempt to read or use a default.");
        }

        Type targetType = parameter.getGenericParameterType(); // 실제 제네릭 타입까지 고려
        Class<?> targetClass = parameter.getParameterType(); // 실제 파라미터의 클래스 타입

        Object body = null;
        boolean bodyReadSuccessfully = false;

        if (this.messageConverters.isEmpty() && requestBodyAnnotation.required()) {
            throw new HttpMessageNotReadableException(
                    "ASEP: No HttpMessageConverters configured to read request body for @SecurityRequestBody, and request body is required.", inputMessage);
        }


        for (HttpMessageConverter<?> converter : this.messageConverters) {
            // HttpMessageConverter<T>의 T는 Object.class로 일반적으로 사용될 수 있음
            if (converter.canRead(targetClass, contentType)) {
                try {
                    // 제네릭 타입을 사용하지 않고 targetClass를 사용 (일반적인 컨버터는 Class<?>를 받음)
                    body = ((HttpMessageConverter<Object>) converter).read((Class<Object>) targetClass, inputMessage);
                    bodyReadSuccessfully = true;
                    if (log.isDebugEnabled()) {
                        log.debug("ASEP: Read HTTP request body with HttpMessageConverter [{}] for parameter type [{}] and content type [{}]",
                                converter.getClass().getSimpleName(), targetClass.getName(), contentType);
                    }
                    break; // 첫 번째로 성공한 컨버터 사용
                } catch (IOException | HttpMessageNotReadableException ex) {
                    // HttpMessageNotReadableException은 Spring에서 제공하는 예외로, 본문 파싱 실패 시 사용
                    log.warn("ASEP: Could not read HTTP request body with HttpMessageConverter [{}]: {}",
                            converter.getClass().getSimpleName(), ex.getMessage());
                    // 여러 컨버터가 있을 수 있으므로, 하나의 실패로 바로 예외를 던지지 않고 다음 컨버터 시도.
                    // 모든 컨버터가 실패하면 아래에서 처리.
                    // 단, 심각한 IOException은 바로 전파하는 것이 나을 수 있음. 여기서는 HttpMessageNotReadableException으로 통일.
                    if (ex instanceof IOException && !(ex instanceof HttpMessageNotReadableException)) {
                        throw new HttpMessageNotReadableException("IO error while reading request body: " + ex.getMessage(), ex, inputMessage);
                    }
                    // HttpMessageNotReadableException은 계속 루프를 돌며 다른 컨버터 시도.
                }
            }
        }

        if (!bodyReadSuccessfully) {
            // 적합한 HttpMessageConverter를 찾지 못했거나 모든 시도 실패
            if (contentType != null) { // Content-Type이 지정되었으나 지원하는 컨버터가 없는 경우
                List<MediaType> supportedMediaTypes = this.messageConverters.stream()
                        .filter(c -> c.canRead(targetClass, null)) // contentType 없이도 읽을 수 있는지 먼저 확인 (일부 컨버터는 가능)
                        // 또는 구체적인 타입을 위해 targetClass 사용
                        .flatMap(c -> c.getSupportedMediaTypes(targetClass).stream())
                        .distinct()
                        .toList();
                throw new HttpMediaTypeNotSupportedException(contentType, supportedMediaTypes);
            } else { // Content-Type도 없고, 어떤 컨버터도 읽을 수 없는 경우 (예: 요청 본문이 비었거나, 빈 컨버터 리스트)
                // 이 경우는 본문이 없다고 간주할 수 있음. required=true일 때만 문제.
            }
        }

        if (body == null && requestBodyAnnotation.required()) {
            // 컨버터가 null을 반환했고 (예: 빈 본문), 파라미터가 필수인 경우
            // 또는 bodyReadSuccessfully가 false인데 required인 경우
            throw new RequestBodyRequiredException(
                    "Request body is required for parameter type " + targetClass.getName() +
                            " but was effectively null or no suitable converter found.", parameter);
        }

        return body;
    }

    /**
     * 요청 본문이 필수일 때, 실제 본문이 없거나 null일 경우 발생하는 예외.
     */
    public static final class RequestBodyRequiredException extends RuntimeException {
        private final transient MethodParameter parameter; // 직렬화에서 제외 (필요시)

        public RequestBodyRequiredException(String message, MethodParameter parameter) {
            super(message);
            this.parameter = parameter;
        }

        public MethodParameter getParameter() { return this.parameter; }
    }
}
