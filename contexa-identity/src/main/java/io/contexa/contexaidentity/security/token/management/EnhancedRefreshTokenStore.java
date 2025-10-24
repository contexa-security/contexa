package io.contexa.contexaidentity.security.token.management;

import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 보안이 강화된 RefreshTokenStore 인터페이스
 *
 * 기존 RefreshTokenStore를 확장하여 다음 기능을 추가:
 * - 토큰 재사용 감지
 * - 토큰 사용 이력 추적
 * - 비정상 패턴 감지
 * - 토큰 체인 관리
 *
 * @since 2024.12
 */
public interface EnhancedRefreshTokenStore extends RefreshTokenStore {

    /**
     * 토큰 갱신 시 사용 (토큰 체인 관리)
     *
     * @param oldToken 이전 토큰
     * @param newToken 새 토큰
     * @param username 사용자명
     * @param deviceId 디바이스 ID
     * @param clientInfo 클라이언트 정보 (IP, User-Agent 등)
     */
    void rotate(String oldToken, String newToken, String username, String deviceId, ClientInfo clientInfo);

    /**
     * 토큰 사용 이력 기록
     *
     * @param token 토큰
     * @param action 액션 (CREATED, USED, ROTATED, BLACKLISTED)
     * @param clientInfo 클라이언트 정보
     */
    void recordUsage(String token, TokenAction action, ClientInfo clientInfo);

    /**
     * 토큰 재사용 감지
     *
     * @param token 토큰
     * @return 이미 사용된 토큰인지 여부
     */
    boolean isTokenReused(String token);

    /**
     * 비정상 패턴 감지
     *
     * @param username 사용자명
     * @param deviceId 디바이스 ID
     * @param clientInfo 현재 클라이언트 정보
     * @return 비정상 패턴 감지 결과
     */
    AnomalyDetectionResult detectAnomaly(String username, String deviceId, ClientInfo clientInfo);

    /**
     * 사용자의 모든 토큰 무효화
     *
     * @param username 사용자명
     * @param reason 무효화 사유
     */
    void revokeAllUserTokens(String username, String reason);

    /**
     * 특정 디바이스의 모든 토큰 무효화
     *
     * @param username 사용자명
     * @param deviceId 디바이스 ID
     * @param reason 무효화 사유
     */
    void revokeDeviceTokens(String username, String deviceId, String reason);

    /**
     * 토큰 사용 이력 조회
     *
     * @param username 사용자명
     * @param limit 조회 개수 제한
     * @return 토큰 사용 이력
     */
    List<TokenUsageHistory> getTokenHistory(String username, int limit);

    /**
     * 활성 세션 정보 조회
     *
     * @param username 사용자명
     * @return 활성 세션 목록
     */
    List<ActiveSession> getActiveSessions(String username);

    /**
     * 토큰 메타데이터 조회
     *
     * @param token 토큰
     * @return 토큰 메타데이터
     */
    Optional<TokenMetadata> getTokenMetadata(String token);

    // ===== 내부 클래스 =====

    /**
     * 클라이언트 정보
     */
    record ClientInfo(
            String ipAddress,
            String userAgent,
            String deviceFingerprint,
            String location,
            Instant timestamp
    ) {}

    /**
     * 토큰 액션
     */
    enum TokenAction {
        CREATED,      // 토큰 생성
        USED,         // 토큰 사용
        ROTATED,      // 토큰 갱신
        REUSED,       // 토큰 재사용 (Refresh Token 재사용 정책)
        BLACKLISTED,  // 블랙리스트 추가
        EXPIRED,      // 만료
        REVOKED       // 취소
    }

    /**
     * 비정상 패턴 감지 결과
     */
    record AnomalyDetectionResult(
            boolean isAnomalous,
            AnomalyType type,
            String description,
            double riskScore
    ) {}

    /**
     * 비정상 패턴 타입
     */
    enum AnomalyType {
        NONE,                    // 정상
        RAPID_REFRESH,          // 짧은 시간 내 반복 갱신
        GEOGRAPHIC_ANOMALY,     // 지리적 이상 (다른 지역에서 동시 사용)
        DEVICE_MISMATCH,        // 디바이스 불일치
        REUSED_TOKEN,           // 재사용된 토큰
        SUSPICIOUS_PATTERN      // 의심스러운 패턴
    }

    /**
     * 토큰 사용 이력
     */
    record TokenUsageHistory(
            String token,
            TokenAction action,
            ClientInfo clientInfo,
            Instant timestamp,
            boolean successful
    ) {}

    /**
     * 활성 세션 정보
     */
    record ActiveSession(
            String deviceId,
            String deviceName,
            String lastIpAddress,
            String location,
            Instant lastActivity,
            Instant createdAt,
            boolean current
    ) {}

    /**
     * 토큰 메타데이터
     */
    record TokenMetadata(
            String username,
            String deviceId,
            Instant issuedAt,
            Instant expiresAt,
            Instant lastUsedAt,
            int usageCount,
            String tokenChainId,  // 토큰 체인 추적용
            boolean isActive
    ) {}
}