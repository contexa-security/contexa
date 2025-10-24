package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class SimpleRedirectSuccessHandler implements AuthenticationSuccessHandler {
    private final String targetUrl;
    private final AuthResponseWriter responseWriter;

    // responseWriter를 받는 생성자만 남기거나, 기본 생성자에서 주입받도록 수정
    public SimpleRedirectSuccessHandler(String targetUrl, AuthResponseWriter responseWriter, boolean dummy) { // 생성자 시그니처 변경 예시 (실제로는 DI 활용)
        Assert.hasText(targetUrl, "targetUrl cannot be empty");
        this.targetUrl = targetUrl;
        this.responseWriter = Objects.requireNonNull(responseWriter, "AuthResponseWriter cannot be null");
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        if (response.isCommitted()) {
            log.debug("Response already committed. Cannot send JSON redirect for target: {}", targetUrl);
            return;
        }
        log.debug("SimpleRedirectSuccessHandler: Sending JSON redirect to {} for user {}", targetUrl, ((UserDto)authentication.getPrincipal()).getUsername());
        // 클라이언트가 JSON 응답을 받고 redirectUrl로 이동하도록 함
        responseWriter.writeSuccessResponse(response,
                Map.of("status", "SUCCESS_REDIRECT_REQUIRED", "message", "성공적으로 처리되었습니다. 지정된 페이지로 이동합니다.", "redirectUrl", targetUrl),
                HttpServletResponse.SC_OK);
    }
}