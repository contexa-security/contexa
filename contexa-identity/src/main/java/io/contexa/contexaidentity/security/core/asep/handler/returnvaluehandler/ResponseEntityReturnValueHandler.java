package io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler;

import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
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

                            }
            return;
        }

        Assert.isInstanceOf(HttpEntity.class, returnValue, "ASEP: HttpEntity expected for ResponseEntityReturnValueHandler");
        HttpEntity<?> responseEntity = (HttpEntity<?>) returnValue;
        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);

        if (responseEntity instanceof ResponseEntity) {
            int statusCodeValue = ((ResponseEntity<?>) responseEntity).getStatusCode().value();
            if (!response.isCommitted()) {
                response.setStatus(statusCodeValue);
            } else if (response.getStatus() != statusCodeValue) {
                log.warn("ASEP: Response already committed with status {}. Ignoring status {} from ResponseEntity.",
                        response.getStatus(), statusCodeValue);
            }
        }

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
            
            if (!response.isCommitted()) {
                outputMessage.getBody(); 
            }
            return;
        }

        Class<?> bodyType = body.getClass();
        MediaType selectedMediaType = null;

        if (entityHeaders.getContentType() != null) {
            selectedMediaType = entityHeaders.getContentType();
        }
        
        else if (resolvedMediaType != null && !resolvedMediaType.isWildcardType() && !resolvedMediaType.isWildcardSubtype()) {
            selectedMediaType = resolvedMediaType;
        }
        
        else {

            List<MediaType> acceptedMediaTypes = Collections.emptyList();
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (StringUtils.hasText(acceptHeader) && !acceptHeader.equals("*/*")) {
                try {
                    acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                    MimeTypeUtils.sortBySpecificity(acceptedMediaTypes);
                } catch (Exception e) {  }
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
            if (selectedMediaType == null) { 
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
            if (selectedMediaType == null) { 
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
                                            }
                    if (!response.isCommitted()) {
                        outputMessage.getBody(); 
                    }
                    return;
                } catch (IOException | HttpMessageNotWritableException ex) {
                    log.error("ASEP: Could not write ResponseEntity body with HttpMessageConverter [{}]: {}",
                            converter.getClass().getSimpleName(), ex.getMessage(), ex);
                    throw new HttpMessageNotWritableException( 
                            "Could not write HttpEntity: " + ex.getMessage(), ex);
                }
            }
        }

        throw new HttpMessageNotWritableException(
                "ASEP: No HttpMessageConverter found for ResponseEntity body type [" +
                        bodyType.getName() + "] and content type [" + selectedMediaType + "]");
    }
}
