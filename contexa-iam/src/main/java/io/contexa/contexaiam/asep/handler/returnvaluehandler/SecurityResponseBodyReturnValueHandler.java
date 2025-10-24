package io.contexa.contexaiam.asep.handler.returnvaluehandler;

import io.contexa.contexaiam.asep.annotation.SecurityResponseBody;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Slf4j
public final class SecurityResponseBodyReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {
    private final List<HttpMessageConverter<?>> messageConverters;

    public SecurityResponseBodyReturnValueHandler(List<HttpMessageConverter<?>> messageConverters) {
        this.messageConverters = Collections.unmodifiableList(
                new ArrayList<>(Objects.requireNonNull(messageConverters, "MessageConverters must not be null"))
        );
        if (this.messageConverters.isEmpty()){
            log.warn("ASEP: HttpMessageConverter list is empty for SecurityResponseBodyReturnValueHandler. Body writing will likely fail.");
        }
    }

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        return (AnnotatedElementUtils.hasAnnotation(returnType.getContainingClass(), SecurityResponseBody.class) ||
                returnType.hasMethodAnnotation(SecurityResponseBody.class));
    }

    @Override
    public void handleReturnValue(@Nullable Object returnValue, MethodParameter returnType,
                                  HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, HandlerMethod handlerMethod,
                                  @Nullable MediaType resolvedMediaType) throws IOException, HttpMessageNotWritableException {
        if (returnValue == null) {
            // @SecurityResponseBody가 있고 반환 값이 null이면, 본문 없이 200 OK 또는 204 No Content.
            // 여기서는 더 이상 아무것도 하지 않음. 필요시 상태 코드 설정.
            log.debug("ASEP: Method [{}] with @SecurityResponseBody returned null. No body will be written.",
                    handlerMethod.getMethod().getName());
            return;
        }

        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);
        MediaType selectedMediaType = resolvedMediaType;

        if (selectedMediaType == null || selectedMediaType.isWildcardType() || selectedMediaType.isWildcardSubtype()) {
            // Fallback logic (ResponseEntityReturnValueHandler와 유사)
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (StringUtils.hasText(acceptHeader) && !acceptHeader.equals("*/*")) {
                try {
                    List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                    MimeTypeUtils.sortBySpecificity(acceptedMediaTypes);
                    if (!acceptedMediaTypes.isEmpty()) selectedMediaType = acceptedMediaTypes.getFirst();
                } catch (Exception e) { /* log and ignore */ }
            }
            if (selectedMediaType == null || selectedMediaType.isWildcardType() || selectedMediaType.isWildcardSubtype()) {
                selectedMediaType = MediaType.APPLICATION_JSON; // Default fallback
            }
            log.warn("ASEP: ResolvedMediaType was not specific for @SecurityResponseBody. Fallback to [{}].", selectedMediaType);
        }

        if (!response.isCommitted()) {
            outputMessage.getHeaders().setContentType(selectedMediaType);
        } else if (!Objects.equals(selectedMediaType, MediaType.valueOf(response.getContentType()))){
            log.warn("ASEP: Response already committed with Content-Type {}. Ignoring determined Content-Type {}.",
                    response.getContentType(), selectedMediaType);
        }


        Class<?> returnValueClass = returnValue.getClass();
        for (HttpMessageConverter converter : this.messageConverters) {
            if (converter.canWrite(returnValueClass, selectedMediaType)) {
                try {
                    ((HttpMessageConverter<Object>) converter).write(returnValue, selectedMediaType, outputMessage);
                    if (log.isDebugEnabled()) {
                        log.debug("ASEP: Written @SecurityResponseBody of type [{}] as '{}' using HttpMessageConverter [{}]",
                                returnValueClass.getSimpleName(), selectedMediaType, converter.getClass().getName());
                    }
                    if (!response.isCommitted()) {
                        outputMessage.getBody(); // Ensure headers are flushed
                    }
                    return;
                } catch (IOException | HttpMessageNotWritableException ex) {
                    log.error("ASEP: Could not write @SecurityResponseBody with HttpMessageConverter [{}]: {}",
                            converter.getClass().getSimpleName(), ex.getMessage(), ex);
                    throw new HttpMessageNotWritableException(
                            "Could not write @SecurityResponseBody: " + ex.getMessage(), ex);
                }
            }
        }

        throw new HttpMessageNotWritableException(
                "ASEP: No HttpMessageConverter found for @SecurityResponseBody return value type [" +
                        returnValueClass.getName() + "] and content type [" + selectedMediaType + "]");
    }
}
