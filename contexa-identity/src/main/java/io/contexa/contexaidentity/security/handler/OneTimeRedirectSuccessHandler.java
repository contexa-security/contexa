package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class OneTimeRedirectSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    private final String targetUrl;
    private final AuthResponseWriter responseWriter; // final로 변경

    // 이 생성자는 AuthResponseWriter를 주입받지 않아 문제가 될 수 있으므로,
    // @Component로 만들고 생성자 주입을 사용하거나, 설정 시 명시적으로 주입해야 함.
    // 여기서는 @RequiredArgsConstructor를 사용하므로 responseWriter도 final 이어야 함.
    // public OneTimeRedirectSuccessHandler(String targetUrl) { ... } // 이 생성자 제거 또는 수정

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException, ServletException {
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to send JSON redirect for target: {}", targetUrl);
            return;
        }
        // responseWriter가 null이 아님을 보장 (생성자에서 주입받으므로)
        Objects.requireNonNull(responseWriter, "AuthResponseWriter must be configured for OneTimeRedirectSuccessHandler.");

        String usernameForLog = (token != null && token.getUsername() != null) ? token.getUsername() : "N/A";
        log.debug("OneTimeRedirectSuccessHandler: Sending JSON redirect to {} after OTT generation for user {}", targetUrl, usernameForLog);
        responseWriter.writeSuccessResponse(response,
                Map.of("status", "OTT_GENERATED_REDIRECT_REQUIRED", "message", "OTT가 생성되었습니다. 지정된 페이지로 이동합니다.", "redirectUrl", targetUrl),
                HttpServletResponse.SC_OK);
    }
}