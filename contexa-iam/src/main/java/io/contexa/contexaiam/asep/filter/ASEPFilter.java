package io.contexa.contexaiam.asep.filter;

import io.contexa.contexaiam.asep.handler.SecurityExceptionHandlerInvoker;
import io.contexa.contexaiam.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;


@Slf4j
@Setter
public final class ASEPFilter extends OncePerRequestFilter implements Ordered {

    private int order = Ordered.LOWEST_PRECEDENCE - 900; // AsepConfigurer보다 더 늦게 (하지만 다른 일반 필터보다는 일찍)

    private final SecurityExceptionHandlerMethodRegistry handlerRegistry;
    private final SecurityExceptionHandlerInvoker handlerInvoker;
    private final List<HttpMessageConverter<?>> messageConverters;

    public ASEPFilter(
            SecurityExceptionHandlerMethodRegistry handlerRegistry,
            SecurityExceptionHandlerInvoker handlerInvoker,
            List<HttpMessageConverter<?>> messageConverters) {
        this.handlerRegistry = Objects.requireNonNull(handlerRegistry, "SecurityExceptionHandlerMethodRegistry cannot be null");
        this.handlerInvoker = Objects.requireNonNull(handlerInvoker, "AsepHandlerAdapter cannot be null");
        // 방어적 복사를 통해 외부 리스트 변경으로부터 안전하게
        this.messageConverters = (messageConverters != null) ? List.copyOf(messageConverters) : Collections.emptyList();
        log.debug("ASEP: ASEPFilter (POJO) initialized. MessageConverters count: {}", this.messageConverters.size());
    }

    @Override
    public int getOrder() {
        return this.order;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (Throwable ex) {
            if (response.isCommitted()) {
                log.warn("ASEP: Response already committed. Unable to handle exception [{}] on path [{}].",
                        ex.getClass().getSimpleName(), request.getRequestURI(), ex);
                // 이 경우 예외를 다시 던지는 것 외에는 할 수 있는 것이 거의 없음.
                // 또는 단순히 반환하여 서블릿 컨테이너의 기본 오류 처리에 맡길 수 있음.
                // 사용자 정의 오류 페이지가 이미 일부 전송되었을 수 있음.
                if (ex instanceof IOException) throw (IOException) ex;
                if (ex instanceof ServletException) throw (ServletException) ex;
                if (ex instanceof RuntimeException) throw (RuntimeException) ex;
                throw new ServletException("Unhandled exception after response committed: " + ex.getMessage(), ex);
            }
            // 응답 버퍼를 클리어할 수 있지만, 매우 신중해야 함 (이미 일부 헤더가 쓰여졌을 수 있음)
            // try { response.resetBuffer(); } catch (IllegalStateException e) { log.trace("Cannot reset buffer for exception handling",e); }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            handleException(request, response, authentication, ex);
        }
    }

    private void handleException(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable exception) throws IOException { // ServletException 대신 IOException
        try {
            log.debug("ASEP: Caught exception [{}] for authentication [{}] on path [{}]",
                    exception.getClass().getName(),
                    (authentication != null ? authentication.getName() : "NONE"),
                    request.getRequestURI());

            HandlerMethod handlerMethod = handlerRegistry.findBestExceptionHandlerMethod(exception, authentication, request);

            if (handlerMethod != null) {
                log.debug("ASEP: Found ASEP handler method [{}] in bean [{}] for exception [{}].",
                        handlerMethod.getMethod().getName(), handlerMethod.getBean().getClass().getSimpleName(),
                        exception.getClass().getSimpleName());

                MediaType resolvedMediaType = determineResponseMediaType(request, handlerMethod);
                this.handlerInvoker.invokeHandlerMethod(request, response, authentication, exception, handlerMethod, resolvedMediaType);

            } else {
                log.debug("ASEP: No specific ASEP handler found for exception [{}]. Using centralized default error response.",
                        exception.getClass().getSimpleName());
                handleCentralizedDefaultErrorResponse(request, response, exception, authentication, false);
            }
        } catch (Exception handlerInvocationException) {
            // 핸들러 실행 중 새로운 예외 발생 시 처리
            log.error("ASEP: Exception occurred while invoking ASEP handler for original exception [{}]: {}. Handler exception: {}",
                    exception.getClass().getSimpleName(), exception.getMessage(),
                    handlerInvocationException.getMessage(), handlerInvocationException);
            if (!response.isCommitted()) {
                // 이 경우, 다시 핸들러를 찾지 않고 중앙 기본 오류 응답으로 처리 (무한 루프 방지)
                handleCentralizedDefaultErrorResponse(request, response, handlerInvocationException, authentication, true);
            } else {
                log.warn("ASEP: Response already committed. Unable to send final default error for handlerInvocationException: {}",
                        handlerInvocationException.getMessage());
            }
        }
    }

    @SuppressWarnings({"rawtypes"})
    private void handleCentralizedDefaultErrorResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            Throwable exception,
            @Nullable Authentication authentication,
            boolean isHandlerError) throws IOException {

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR; // 기본값
        String errorCode = "INTERNAL_SERVER_ERROR";
        String baseMessage = isHandlerError ? "Error occurred in ASEP exception handler" : "An unexpected error occurred";
        String detailMessage = exception.getMessage();

        if (exception instanceof AuthenticationException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = "UNAUTHENTICATED";
            baseMessage = "Authentication failed";
            SecurityContextHolder.clearContext(); // 인증 실패 시 컨텍스트 클리어
            log.debug("ASEP: Cleared SecurityContext due to AuthenticationException.");
        } else if (exception instanceof AccessDeniedException) {
            status = HttpStatus.FORBIDDEN;
            errorCode = "ACCESS_DENIED";
            baseMessage = "Access denied";
        }
        // TODO: 필요시 다른 특정 예외 타입에 대한 상태 코드 및 메시지 매핑 추가
        // (예: HttpMediaTypeNotSupportedException -> HttpStatus.UNSUPPORTED_MEDIA_TYPE)
        // (예: HttpMessageNotReadableException -> HttpStatus.BAD_REQUEST)

        // 응답이 이미 시작되지 않았다면 상태 코드 설정
        if (!response.isCommitted()) {
            response.setStatus(status.value());
        } else {
            log.warn("ASEP: Response already committed (status {}). Cannot set new status {} for default error response.",
                    response.getStatus(), status.value());
            return; // 이미 응답 시작되었으면 더 이상 처리 불가
        }

        Map<String, Object> errorAttributes = new LinkedHashMap<>();
        errorAttributes.put("timestamp", System.currentTimeMillis());
        errorAttributes.put("status", status.value());
        errorAttributes.put("error", errorCode);
        errorAttributes.put("message", baseMessage + (detailMessage != null && !detailMessage.isBlank() ? ": " + detailMessage : ""));
        errorAttributes.put("path", request.getRequestURI());
        errorAttributes.put("exception", exception.getClass().getName()); // 개발/디버그 시 유용
        // if (isHandlerError) errorAttributes.put("handlerErrorCause", true);

        MediaType bestMatchingMediaType = determineBestMediaTypeForDefaultResponse(request);
        response.setContentType(bestMatchingMediaType.toString());

        boolean written = false;
        if (!this.messageConverters.isEmpty()) {
            ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);
            for (HttpMessageConverter converter : this.messageConverters) {
                if (converter.canWrite(errorAttributes.getClass(), bestMatchingMediaType)) {
                    try {
                        ((HttpMessageConverter<Object>) converter).write(errorAttributes, bestMatchingMediaType, outputMessage);
                        written = true;
                        log.debug("ASEP: Default error response written with HttpMessageConverter [{}] as {}",
                                converter.getClass().getSimpleName(), bestMatchingMediaType);
                        break;
                    } catch (HttpMessageNotWritableException | IOException e) {
                        log.error("ASEP: Error writing default error response with HttpMessageConverter [{}]: {}",
                                converter.getClass().getSimpleName(), e.getMessage(), e);
                    }
                }
            }
        }

        if (!written) {
            log.warn("ASEP: No suitable HttpMessageConverter found or response committed before writing. " +
                            "Sending plain text default error for [{}]. Target MediaType: {}",
                    exception.getClass().getSimpleName(), bestMatchingMediaType);
            if (!response.isCommitted()) {
                response.setContentType(MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8");
                try (PrintWriter writer = response.getWriter()) {
                    writer.println("Status: " + status.value());
                    writer.println("Error: " + errorCode);
                    writer.println("Message: " + baseMessage + (detailMessage != null && !detailMessage.isBlank() ? ": " + detailMessage : ""));
                    writer.println("Path: " + request.getRequestURI());
                    writer.println("Exception: " + exception.getClass().getName());
                } catch (IOException ex) {
                    log.error("ASEP: Failed to write plain text error response.", ex);
                }
            }
        }

        log.info("ASEP: Sent centralized default error response: status={}, type={}, message='{}', path='{}'",
                status, exception.getClass().getSimpleName(), baseMessage, request.getRequestURI());
    }


    private MediaType determineResponseMediaType(HttpServletRequest request, HandlerMethod handlerMethod) {
        List<MediaType> acceptedMediaTypes = Collections.singletonList(MediaType.ALL); // 기본값
        String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
        if (acceptHeader != null && !acceptHeader.trim().isEmpty()) {
            try {
                List<MediaType> parsedAccepted = MediaType.parseMediaTypes(acceptHeader);
                if (!CollectionUtils.isEmpty(parsedAccepted)) {
                    MimeTypeUtils.sortBySpecificity(parsedAccepted);
                    acceptedMediaTypes = parsedAccepted;
                }
            } catch (Exception e) {
                log.warn("ASEP: Could not parse Accept header [{}]. Using default [{}].", acceptHeader, acceptedMediaTypes, e);
            }
        }

        // 핸들러에 produces가 명시된 경우
        if (handlerMethod != null && !CollectionUtils.isEmpty(handlerMethod.getProduces())) {
            List<MediaType> handlerProduces = handlerMethod.getProduces().stream()
                    .map(MediaType::parseMediaType) // 여기서 InvalidMediaTypeException 발생 가능성 있음 (어노테이션 값 검증 필요)
                    .toList();

            for (MediaType acceptedType : acceptedMediaTypes) {
                for (MediaType producedType : handlerProduces) {
                    if (acceptedType.isCompatibleWith(producedType)) {
                        // 실제 변환 가능한지 HttpMessageConverter로 확인 (선택적)
                        for (HttpMessageConverter<?> converter : this.messageConverters) {
                            // 실제 반환될 객체 타입을 알 수 없으므로 Object.class 또는 Map.class 등으로 가정
                            if (converter.canWrite(Object.class, producedType)) {
                                return producedType.removeQualityValue();
                            }
                        }
                    }
                }
            }
            // Accept 헤더와 매칭되는 것이 없으면, 핸들러가 명시한 첫번째 produce 타입을 반환 (만약 변환 가능하다면)
            if (!handlerProduces.isEmpty()) {
                MediaType firstProduce = handlerProduces.get(0).removeQualityValue();
                for (HttpMessageConverter<?> converter : this.messageConverters) {
                    if (converter.canWrite(Object.class, firstProduce)) return firstProduce;
                }
            }
        }
        // 핸들러에 produces가 없거나 매칭 안되면, Accept 헤더 기반으로 시스템 기본 지원 타입 시도
        return determineBestMediaTypeForDefaultResponse(request);
    }

    private MediaType determineBestMediaTypeForDefaultResponse(HttpServletRequest request) {
        List<MediaType> acceptedMediaTypes = Collections.singletonList(MediaType.APPLICATION_JSON); // 기본값
        String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
        if (acceptHeader != null && !acceptHeader.trim().isEmpty()) {
            try {
                List<MediaType> parsedAccepted = MediaType.parseMediaTypes(acceptHeader);
                if (!CollectionUtils.isEmpty(parsedAccepted)) {
                    MimeTypeUtils.sortBySpecificity(parsedAccepted);
                    acceptedMediaTypes = parsedAccepted;
                }
            } catch (Exception e) {
                log.warn("ASEP: Could not parse Accept header [{}] for default response. Using default [{}].",
                        acceptHeader, acceptedMediaTypes.get(0), e);
            }
        }

        for (MediaType acceptedType : acceptedMediaTypes) {
            // 와일드카드 타입이 아닌 구체적인 타입을 우선적으로 찾음
            if (!acceptedType.isWildcardType() && !acceptedType.isWildcardSubtype()) {
                for (HttpMessageConverter<?> converter : this.messageConverters) {
                    if (converter.canWrite(Map.class, acceptedType)) { // 오류 객체는 보통 Map 또는 POJO
                        return acceptedType.removeQualityValue();
                    }
                }
            }
        }
        // 구체적인 타입 매칭 실패 시, 호환되는 타입 중 컨버터가 지원하는 첫 번째 타입
        for (MediaType acceptedType : acceptedMediaTypes) {
            for (HttpMessageConverter<?> converter : this.messageConverters) {
                for(MediaType supported : converter.getSupportedMediaTypes(Map.class)) { // Map.class 대신 실제 오류객체 타입
                    if (acceptedType.isCompatibleWith(supported) && !supported.isWildcardType() && !supported.isWildcardSubtype()) {
                        return supported.removeQualityValue();
                    }
                }
            }
        }

        // 최후의 기본값 (JSON을 지원하는 컨버터가 있다면 JSON)
        for (HttpMessageConverter<?> converter : this.messageConverters) {
            if (converter.canWrite(Map.class, MediaType.APPLICATION_JSON)) return MediaType.APPLICATION_JSON;
        }
        // 정말 아무것도 없으면 OCTET_STREAM (거의 발생하지 않아야 함)
        return MediaType.APPLICATION_OCTET_STREAM;
    }
}
