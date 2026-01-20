package io.contexa.contexaidentity.security.core.asep.filter;

import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerInvoker;
import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
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

    private int order = Ordered.LOWEST_PRECEDENCE - 900; 

    private final SecurityExceptionHandlerMethodRegistry handlerRegistry;
    private final SecurityExceptionHandlerInvoker handlerInvoker;
    private final List<HttpMessageConverter<?>> messageConverters;

    public ASEPFilter(
            SecurityExceptionHandlerMethodRegistry handlerRegistry,
            SecurityExceptionHandlerInvoker handlerInvoker,
            List<HttpMessageConverter<?>> messageConverters) {
        this.handlerRegistry = Objects.requireNonNull(handlerRegistry, "SecurityExceptionHandlerMethodRegistry cannot be null");
        this.handlerInvoker = Objects.requireNonNull(handlerInvoker, "AsepHandlerAdapter cannot be null");
        
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
                
                
                
                if (ex instanceof IOException) throw (IOException) ex;
                if (ex instanceof ServletException) throw (ServletException) ex;
                if (ex instanceof RuntimeException) throw (RuntimeException) ex;
                throw new ServletException("Unhandled exception after response committed: " + ex.getMessage(), ex);
            }
            
            

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            handleException(request, response, authentication, ex);
        }
    }

    private void handleException(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable exception) throws IOException { 
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
            
            log.error("ASEP: Exception occurred while invoking ASEP handler for original exception [{}]: {}. Handler exception: {}",
                    exception.getClass().getSimpleName(), exception.getMessage(),
                    handlerInvocationException.getMessage(), handlerInvocationException);
            if (!response.isCommitted()) {
                
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

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR; 
        String errorCode = "INTERNAL_SERVER_ERROR";
        String baseMessage = isHandlerError ? "Error occurred in ASEP exception handler" : "An unexpected error occurred";
        String detailMessage = exception.getMessage();

        if (exception instanceof AuthenticationException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = "UNAUTHENTICATED";
            baseMessage = "Authentication failed";
            SecurityContextHolder.clearContext(); 
            log.debug("ASEP: Cleared SecurityContext due to AuthenticationException.");
        } else if (exception instanceof AccessDeniedException) {
            status = HttpStatus.FORBIDDEN;
            errorCode = "ACCESS_DENIED";
            baseMessage = "Access denied";
        }
        
        
        

        
        if (!response.isCommitted()) {
            response.setStatus(status.value());
        } else {
            log.warn("ASEP: Response already committed (status {}). Cannot set new status {} for default error response.",
                    response.getStatus(), status.value());
            return; 
        }

        Map<String, Object> errorAttributes = new LinkedHashMap<>();
        errorAttributes.put("timestamp", System.currentTimeMillis());
        errorAttributes.put("status", status.value());
        errorAttributes.put("error", errorCode);
        errorAttributes.put("message", baseMessage + (detailMessage != null && !detailMessage.isBlank() ? ": " + detailMessage : ""));
        errorAttributes.put("path", request.getRequestURI());
        errorAttributes.put("exception", exception.getClass().getName()); 
        

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
        List<MediaType> acceptedMediaTypes = Collections.singletonList(MediaType.ALL); 
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

        
        if (handlerMethod != null && !CollectionUtils.isEmpty(handlerMethod.getProduces())) {
            List<MediaType> handlerProduces = handlerMethod.getProduces().stream()
                    .map(MediaType::parseMediaType) 
                    .toList();

            for (MediaType acceptedType : acceptedMediaTypes) {
                for (MediaType producedType : handlerProduces) {
                    if (acceptedType.isCompatibleWith(producedType)) {
                        
                        for (HttpMessageConverter<?> converter : this.messageConverters) {
                            
                            if (converter.canWrite(Object.class, producedType)) {
                                return producedType.removeQualityValue();
                            }
                        }
                    }
                }
            }
            
            if (!handlerProduces.isEmpty()) {
                MediaType firstProduce = handlerProduces.get(0).removeQualityValue();
                for (HttpMessageConverter<?> converter : this.messageConverters) {
                    if (converter.canWrite(Object.class, firstProduce)) return firstProduce;
                }
            }
        }
        
        return determineBestMediaTypeForDefaultResponse(request);
    }

    private MediaType determineBestMediaTypeForDefaultResponse(HttpServletRequest request) {
        List<MediaType> acceptedMediaTypes = Collections.singletonList(MediaType.APPLICATION_JSON); 
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
            
            if (!acceptedType.isWildcardType() && !acceptedType.isWildcardSubtype()) {
                for (HttpMessageConverter<?> converter : this.messageConverters) {
                    if (converter.canWrite(Map.class, acceptedType)) { 
                        return acceptedType.removeQualityValue();
                    }
                }
            }
        }
        
        for (MediaType acceptedType : acceptedMediaTypes) {
            for (HttpMessageConverter<?> converter : this.messageConverters) {
                for(MediaType supported : converter.getSupportedMediaTypes(Map.class)) { 
                    if (acceptedType.isCompatibleWith(supported) && !supported.isWildcardType() && !supported.isWildcardSubtype()) {
                        return supported.removeQualityValue();
                    }
                }
            }
        }

        
        for (HttpMessageConverter<?> converter : this.messageConverters) {
            if (converter.canWrite(Map.class, MediaType.APPLICATION_JSON)) return MediaType.APPLICATION_JSON;
        }
        
        return MediaType.APPLICATION_OCTET_STREAM;
    }
}
