package io.contexa.contexaidentity.security.properties;

import io.contexa.contexaidentity.security.enums.*;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "spring.auth")
public class AuthContextProperties {

    /**
     * 인증 상태 유지 방식 선택 (JWT, SESSION)
     */
    private StateType stateType = StateType.JWT;

    /**
     * 인증 상태 유지 방식 선택 (JWT, SESSION)
     */
    private TokenTransportType tokenTransportType = TokenTransportType.HEADER;

    /**
     * 토큰 발급/검증의 방식 설정
     */
    private TokenIssuer tokenIssuer = TokenIssuer.INTERNAL;

    /**
     * 토큰 저장소 타입 설정 (MEMORY, REDIS)
     * - MEMORY: 기존 방식, 서버 메모리에 저장 (단일 서버 환경)
     * - REDIS: Redis를 활용한 분산 저장 (다중 서버 환경)
     * @since 2024.12 - Redis 지원 추가
     */
    private TokenStoreType tokenStoreType = TokenStoreType.REDIS;
    private FactorSelectionType factorSelectionType = FactorSelectionType.SELECT;

    /**
     * MFA 관련 설정
     */
    @NestedConfigurationProperty
    private MfaSettings mfa = new MfaSettings(); // 기본 인스턴스 생성

    /**
     * JWT 등 외부 토큰 기반 인증 설정
     */
    @NestedConfigurationProperty
    private JwtsTokenSettings internal = new JwtsTokenSettings();



    /**
     * OAuth2 Resource Server 기반 자동 토큰 처리 (internal) 설정
     */
    @NestedConfigurationProperty
    private OAuth2TokenSettings oauth2 = new OAuth2TokenSettings();

    private long accessTokenValidity = 3600000;       // 1시간
    private long refreshTokenValidity = 604800000;    // 7일
    private long refreshRotateThreshold = 43200000; // 기본 12시간 (밀리초)

    private boolean enableRefreshToken = true;
    private boolean allowMultipleLogins = false;
    private int maxConcurrentLogins = 3;
    private boolean cookieSecure = false;


    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";

}


