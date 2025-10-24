package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;

public interface TokenTransportStrategy {

    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);

    /**
     * 액세스 토큰과 리프레시 토큰을 전송하기 위한 정보를 준비합니다.
     * @param accessToken 액세스 토큰
     * @param refreshToken 리프레시 토큰
     * @param tokenServiceProperties 토큰 유효기간 등 필요한 속성 접근용 (순환참조 회피)
     * @return TokenTransportResult 객체
     */
    TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken, TokenService.TokenServicePropertiesProvider tokenServiceProperties);

    /**
     * 클라이언트의 토큰들을 클리어하기 위한 정보를 준비합니다.
     * @param tokenServiceProperties 쿠키 경로 등 필요한 속성 접근용
     * @return TokenTransportResult 객체
     */
    TokenTransportResult prepareTokensForClear(TokenService.TokenServicePropertiesProvider tokenServiceProperties);
}


