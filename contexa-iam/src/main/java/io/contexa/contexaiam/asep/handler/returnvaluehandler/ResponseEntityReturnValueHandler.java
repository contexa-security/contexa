package io.contexa.contexaiam.asep.handler.returnvaluehandler;

import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Slf4j
public final class ResponseEntityReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {
    private final List<HttpMessageConverter<?>> messageConverters;

    public ResponseEntityReturnValueHandler(List<HttpMessageConverter<?>> messageConverters) {
        this.messageConverters = Collections.unmodifiableList(
                new ArrayList<>(Objects.requireNonNull(messageConverters, "MessageConverters must not be null"))
        );
        if (this.messageConverters.isEmpty()){
            log.warn("ASEP: HttpMessageConverter list is empty for ResponseEntityReturnValueHandler. Body writing will likely fail.");
        }
    }

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        return HttpEntity.class.isAssignableFrom(returnType.getParameterType());
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void handleReturnValue(@Nullable Object returnValue, MethodParameter returnType,
                                  HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, HandlerMethod handlerMethod,
                                  @Nullable MediaType resolvedMediaType) throws IOException, HttpMessageNotWritableException {
        if (returnValue == null) {
            if (!response.isCommitted()) {
                // Spring MVC의 HttpEntityMethodProcessor는 returnValue가 null이면 (HttpEntity 자체가 null)
                // 헤더만 쓰고 본문은 쓰지 않음. 상태 코드는 ResponseEntity에 명시된 것을 따름.
                // 만약 ResponseEntity가 아닌 HttpEntity가 null이면, 이 핸들러는 응답을 완료된 것으로 간주.
                // 여기서는 HttpEntity가 null이면 아무것도 하지 않음 (응답이 이미 처리되었거나, 다른 핸들러가 처리할 수 있도록)
                log.debug("ASEP: HttpEntity return value is null for method [{}]. Response might have been handled directly or no content to send.",
                        handlerMethod.getMethod().getName());
            }
            return;
        }

        Assert.isInstanceOf(HttpEntity.class, returnValue, "ASEP: HttpEntity expected for ResponseEntityReturnValueHandler");
        HttpEntity<?> responseEntity = (HttpEntity<?>) returnValue;
        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);

        // 상태 코드 설정 (ResponseEntity인 경우에만)
        if (responseEntity instanceof ResponseEntity) {
            int statusCodeValue = ((ResponseEntity<?>) responseEntity).getStatusCode().value();
            if (!response.isCommitted()) {
                response.setStatus(statusCodeValue);
            } else if (response.getStatus() != statusCodeValue) {
                log.warn("ASEP: Response already committed with status {}. Ignoring status {} from ResponseEntity.",
                        response.getStatus(), statusCodeValue);
            }
        }

        // 헤더 설정
        HttpHeaders entityHeaders = responseEntity.getHeaders();
        if (!entityHeaders.isEmpty()) {
            if (!response.isCommitted()) {
                outputMessage.getHeaders().putAll(entityHeaders);
            } else {
                log.warn("ASEP: Response already committed. Ignoring headers from ResponseEntity: {}", entityHeaders);
            }
        }

        Object body = responseEntity.getBody();
        if (body == null) {
            // Ensure headers are flushed, an I/O call might be needed for some Servlet containers
            if (!response.isCommitted()) {
                outputMessage.getBody(); // May flush headers
            }
            return;
        }

        // 본문 직렬화
        Class<?> bodyType = body.getClass();
        MediaType selectedMediaType = null;

        // 1. ResponseEntity 헤더에 Content-Type이 명시되어 있으면 그것을 우선 사용
        if (entityHeaders.getContentType() != null) {
            selectedMediaType = entityHeaders.getContentType();
        }
        // 2. AsepHandlerAdapter에서 전달된 resolvedMediaType (Content Negotiation 결과) 사용
        else if (resolvedMediaType != null && !resolvedMediaType.isWildcardType() && !resolvedMediaType.isWildcardSubtype()) {
            selectedMediaType = resolvedMediaType;
        }
        // 3. 위 두 경우가 없으면, Accept 헤더와 messageConverters를 기반으로 다시 결정 시도
        else {
            // 이 로직은 ASEPFilter의 determineBestMediaTypeForDefaultResponse와 유사할 수 있음
            // 또는 간단히 application/json으로 fallback
            List<MediaType> acceptedMediaTypes = Collections.emptyList();
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (StringUtils.hasText(acceptHeader) && !acceptHeader.equals("*/*")) {
                try {
                    acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                    MimeTypeUtils.sortBySpecificity(acceptedMediaTypes);
                } catch (Exception e) { /* log and ignore */ }
            }

            for (MediaType accepted : acceptedMediaTypes) {
                for (HttpMessageConverter<?> converter : this.messageConverters) {
                    if (converter.canWrite(bodyType, accepted)) {
                        selectedMediaType = accepted;
                        break;
                    }
                }
                if (selectedMediaType != null) break;
            }
            if (selectedMediaType == null) { // 정말 못찾겠으면 JSON 또는 첫번째 컨버터 지원 타입
                for (HttpMessageConverter<?> converter : this.messageConverters) {
                    if (converter.canWrite(bodyType, MediaType.APPLICATION_JSON)) {
                        selectedMediaType = MediaType.APPLICATION_JSON;
                        break;
                    }
                    List<MediaType> supported = converter.getSupportedMediaTypes(bodyType);
                    if (!supported.isEmpty() && !supported.get(0).isWildcardType()) {
                        selectedMediaType = supported.get(0);
                        break;
                    }
                }
            }
            if (selectedMediaType == null) { // 최후의 수단
                selectedMediaType = MediaType.APPLICATION_OCTET_STREAM;
            }
            log.warn("ASEP: ContentType not specified in ResponseEntity and no specific resolvedMediaType. Fallback to [{}].", selectedMediaType);
        }

        if (!response.isCommitted()) {
            outputMessage.getHeaders().setContentType(selectedMediaType);
        } else if (!Objects.equals(selectedMediaType, MediaType.valueOf(response.getContentType()))) {
            log.warn("ASEP: Response already committed with Content-Type {}. Ignoring determined Content-Type {}.",
                    response.getContentType(), selectedMediaType);
        }


        for (HttpMessageConverter converter : this.messageConverters) {
            if (converter.canWrite(bodyType, selectedMediaType)) {
                try {
                    ((HttpMessageConverter<Object>) converter).write(body, selectedMediaType, outputMessage);
                    if (log.isDebugEnabled()) {
                        log.debug("ASEP: Written ResponseEntity body of type [{}] as '{}' using HttpMessageConverter [{}]",
                                bodyType.getSimpleName(), selectedMediaType, converter.getClass().getName());
                    }
                    if (!response.isCommitted()) {
                        outputMessage.getBody(); // Ensure headers are flushed
                    }
                    return;
                } catch (IOException | HttpMessageNotWritableException ex) {
                    log.error("ASEP: Could not write ResponseEntity body with HttpMessageConverter [{}]: {}",
                            converter.getClass().getSimpleName(), ex.getMessage(), ex);
                    throw new HttpMessageNotWritableException( // Spring의 예외 사용
                            "Could not write HttpEntity: " + ex.getMessage(), ex);
                }
            }
        }

        throw new HttpMessageNotWritableException(
                "ASEP: No HttpMessageConverter found for ResponseEntity body type [" +
                        bodyType.getName() + "] and content type [" + selectedMediaType + "]");
    }
}
