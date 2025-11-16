package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 단일 인증용 OAuth2 토큰 기반 성공 핸들러
 *
 * FORM, REST, OTT, PASSKEY 공용으로 사용
 * 세션 기반이 아닌 OAuth2/JWT 토큰 기반 인증 처리
 * MFA 기능 일체 제외
 */
@Slf4j
@Component
public class OAuth2SingleAuthSuccessHandler extends AbstractTokenBasedSuccessHandler {

    public OAuth2SingleAuthSuccessHandler(TokenService tokenService,
                                          AuthResponseWriter responseWriter,
                                          AuthContextProperties authContextProperties) {
        super(tokenService, responseWriter, authContextProperties);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult providedResult) throws IOException {

        if (response.isCommitted()) {
            log.warn("Response already committed for user: {}", authentication.getName());
            return;
        }

        log.debug("Processing OAuth2 single auth success for user: {}", authentication.getName());

        // 1. 토큰 생성 (부모 클래스 공통 로직 사용)
        TokenPair tokenPair = createTokenPair(authentication, null, request, response);
        TokenTransportResult transportResult = prepareTokenTransport(
                tokenPair.getAccessToken(), tokenPair.getRefreshToken());

        // 2. 응답 데이터 구성
        Map<String, Object> responseData = buildResponseData(transportResult, authentication, request);

        // 3. 쿠키 설정 및 JSON 응답 (부모 클래스 공통 로직 사용)
        setCookies(response, transportResult);
        writeJsonResponse(response, responseData);

        log.debug("OAuth2 single auth success completed for user: {}", authentication.getName());
    }

    @Override
    protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                     Authentication authentication,
                                                     HttpServletRequest request) {

        Map<String, Object> responseData = new HashMap<>();

        // TokenTransportResult body에 토큰 정보 포함
        if (transportResult != null && transportResult.getBody() != null) {
            responseData.putAll(transportResult.getBody());
        }

        // DefaultRestLoginPageGeneratingFilter JavaScript 호환 필수 필드
        responseData.put("authenticated", true);
        responseData.put("redirectUrl", determineTargetUrl(request));
        responseData.put("message", "로그인 성공!");
        responseData.put("username", authentication.getName());

        log.debug("Response data built with accessToken: {}", responseData.containsKey("accessToken"));

        return responseData;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request) {
        // AuthContextProperties에서 단일 인증 성공 URL 가져오기
        String successUrl = authContextProperties.getUrls().getSingle().getLoginSuccess();
        return request.getContextPath() + successUrl;
    }
}
