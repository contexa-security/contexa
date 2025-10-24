package io.contexa.contexaiam.asep.handler.returnvaluehandler;

import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
public final class RedirectReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {
    private static final String REDIRECT_URL_PREFIX = "redirect:";

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        // String 타입을 반환하는 경우 우선 지원 대상으로 간주.
        // 실제 redirect 처리는 handleReturnValue에서 값 확인 후 결정.
        return String.class.isAssignableFrom(returnType.getParameterType());
    }

    @Override
    public void handleReturnValue(@Nullable Object returnValue, MethodParameter returnType,
                                  HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, HandlerMethod handlerMethod,
                                  @Nullable MediaType resolvedMediaType) throws IOException {
        if (returnValue == null) {
            log.debug("ASEP: Redirect target URL is null for method [{}], nothing to do.", handlerMethod.getMethod().getName());
            return;
        }

        String url = returnValue.toString();
        if (!url.startsWith(REDIRECT_URL_PREFIX)) {
            // 이 핸들러는 "redirect:"로 시작하는 문자열만 처리.
            // 만약 다른 String 반환 값 핸들러가 우선순위가 낮게 설정되어 있다면,
            // 이 핸들러가 먼저 호출될 수 있으므로, 여기서 실제 처리를 하지 않고 반환해야 함.
            // AsepHandlerAdapter는 첫 번째 supportsReturnType=true인 핸들러를 사용하므로,
            // 이 핸들러의 우선순위가 다른 String 처리 핸들러보다 낮거나,
            // supportsReturnType에서 더 정확한 조건(예: 어노테이션)을 확인해야 함.
            // 현재는 "redirect:"가 아니면 아무것도 하지 않음 (문제가 될 수 있음).
            log.trace("ASEP: Return value for method [{}] does not start with 'redirect:'. RedirectReturnValueHandler will not process it.",
                    handlerMethod.getMethod().getName());
            // 이 경우, AsepHandlerAdapter는 다른 핸들러를 찾지 않고 여기서 종료될 수 있으므로,
            // 만약 다른 String 반환 (예: view name)을 지원하려면 별도의 핸들러와 우선순위 관리가 필요.
            // 또는 이 핸들러의 우선순위를 매우 낮게 설정.
            // 여기서는 다른 String 핸들러가 없다고 가정하고, redirect 아니면 무시.
            return;
        }

        String redirectUrl = url.substring(REDIRECT_URL_PREFIX.length());
        if (response.isCommitted()) {
            log.warn("ASEP: Response already committed. Ignoring redirect to [{}] for method [{}].",
                    redirectUrl, handlerMethod.getMethod().getName());
            return;
        }

        // URL 재작성 및 인코딩 (컨텍스트 패스 등 고려)
        String encodedRedirectUrl;
        try {
            encodedRedirectUrl = response.encodeRedirectURL(
                    UriComponentsBuilder.fromUriString(redirectUrl).build().toUriString()
            );
        } catch (IllegalArgumentException e) {
            log.error("ASEP: Invalid redirect URL string [{}]. Cannot encode.", redirectUrl, e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Invalid redirect URL format");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("ASEP: Redirecting from method [{}] to [{}].",
                    handlerMethod.getMethod().getName(), encodedRedirectUrl);
        }
        response.sendRedirect(encodedRedirectUrl);
    }
}
