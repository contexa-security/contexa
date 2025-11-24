package io.contexa.contexacommon.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * 완전 일원화된 MFA 설정
 * - State Machine 기반 MFA를 위한 모든 설정 통합
 * - 세션 관리, 보안, 타임아웃 등 포함
 */
@Getter
@Setter
public class MfaSettings {

    // === URL 설정 ===
    /**
     * MFA 관련 URL 설정
     */
    @NestedConfigurationProperty
    private MfaUrls urls = new MfaUrls();

    // === 세션 및 타임아웃 설정 ===
    /**
     * MFA 세션 전체 타임아웃 (밀리초)
     * 기본값: 10분
     */
    private long sessionTimeoutMs = TimeUnit.MINUTES.toMillis(10);

    /**
     * 팩터 챌린지 타임아웃 (밀리초)
     * 각 팩터별 검증 제한 시간
     * 기본값: 5분
     */
    private long challengeTimeoutMs = TimeUnit.MINUTES.toMillis(5);
    private long inactivityTimeout = TimeUnit.MINUTES.toMillis(15);
    private long cacheTtl = TimeUnit.MINUTES.toMillis(5);

    /**
     * 세션 갱신 간격 (밀리초)
     * 마지막 활동 후 이 시간마다 세션 갱신 가능
     * 기본값: 30초
     */
    private long sessionRefreshIntervalMs = TimeUnit.SECONDS.toMillis(30);

    /**
     * State Machine 작업 타임아웃 (밀리초)
     * State Machine 연산의 최대 대기 시간
     * 기본값: 10초
     */
    private long stateMachineTimeoutMs = TimeUnit.SECONDS.toMillis(10);

    // === 보안 설정 ===
    /**
     * 최대 재시도 횟수
     * 각 팩터별 최대 검증 실패 허용 횟수
     */
    private int maxRetryAttempts = 5;

    /**
     * 계정 잠금 시간 (밀리초)
     * 최대 재시도 초과 시 계정 잠금 시간
     * 기본값: 15분
     */
    private long accountLockoutDurationMs = TimeUnit.MINUTES.toMillis(15);

    /**
     * 브루트 포스 공격 방지를 위한 최소 지연 시간 (밀리초)
     * 각 검증 시도 사이의 최소 대기 시간
     * 기본값: 500ms
     */
    private long minimumDelayMs = 500L;

    /**
     * 디바이스 기억 기간 (밀리초)
     * 신뢰할 수 있는 디바이스로 등록된 기간
     * 기본값: 30일
     */
    private long deviceRememberDurationMs = TimeUnit.DAYS.toMillis(30);

    // === 토큰 설정 ===
    /**
     * MFA OTT 코드의 유효 시간 (초 단위)
     */
    private int otpTokenValiditySeconds = 300; // 기본 5분

    /**
     * OTP 토큰 길이
     */
    private int otpTokenLength = 6;

    /**
     * SMS 재전송 허용 간격 (초)
     */
    private int smsResendIntervalSeconds = 60;

    /**
     * 이메일 재전송 허용 간격 (초)
     */
    private int emailResendIntervalSeconds = 120;

    // === State Machine 설정 ===
    /**
     * State Machine 풀 크기
     * 동시 처리 가능한 MFA 세션 수
     */
    private int stateMachinePoolSize = 100;

    /**
     * State Machine 캐시 TTL (밀리초)
     * 상태 캐시 유지 시간
     */
    private long stateMachineCacheTtlMs = TimeUnit.MINUTES.toMillis(5);

    /**
     * Circuit Breaker 실패 임계값
     * 연속 실패 횟수가 이 값을 초과하면 Circuit Breaker 오픈
     */
    private int circuitBreakerFailureThreshold = 5;

    /**
     * Circuit Breaker 타임아웃 (초)
     * Circuit Breaker가 열린 후 재시도까지 대기 시간
     */
    private int circuitBreakerTimeoutSeconds = 30;

    // === 로깅 및 모니터링 설정 ===
    /**
     * 상세 로깅 활성화
     * 디버깅용 상세 로그 출력 여부
     */
    private boolean detailedLoggingEnabled = false;

    /**
     * 성능 메트릭 수집 활성화
     * State Machine 성능 메트릭 수집 여부
     */
    private boolean metricsEnabled = true;

    /**
     * 감사 로그 활성화
     * 보안 관련 이벤트 감사 로그 출력 여부
     */
    private boolean auditLoggingEnabled = true;

    /**
     * 세션 저장소 타입 선택
     * - http-session: HTTP Session 사용 (기본값, 단일 서버)
     * - redis: Redis 사용 (분산 환경)
     * - memory: In-Memory 사용 (개발/테스트)
     * - auto: 환경에 따라 자동 선택
     */
    private String sessionStorageType = "http-session";

    /**
     * Repository 자동 선택 활성화
     * true: 환경을 분석해서 최적의 Repository 자동 선택
     * false: sessionStorageType 설정값만 사용
     */
    private boolean autoSelectRepository = false;

    /**
     * Repository 선택 우선순위 (쉼표로 구분)
     * 예: "redis,memory,http-session"
     */
    private String repositoryPriority = "redis,memory,http-session";

    /**
     * Fallback Repository 타입
     * 설정된 Repository 생성 실패 시 사용
     */
    private String fallbackRepositoryType = "http-session";

    // === Repository별 세부 설정 ===

    @NestedConfigurationProperty
    private HttpSessionSettings httpSession = new HttpSessionSettings();

    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    @NestedConfigurationProperty
    private MemorySettings memory = new MemorySettings();

    /**
     * SMS 팩터 설정
     */
    @NestedConfigurationProperty
    private SmsFactorSettings smsFactor = new SmsFactorSettings();

    /**
     * 이메일 팩터 설정
     */
    @NestedConfigurationProperty
    private EmailFactorSettings emailFactor = new EmailFactorSettings();

    // === 편의 메서드들 ===

    /**
     * 세션 타임아웃을 Duration으로 반환
     */
    public Duration getSessionTimeout() {
        return Duration.ofMillis(sessionTimeoutMs);
    }

    /**
     * 챌린지 타임아웃을 Duration으로 반환
     */
    public Duration getChallengeTimeout() {
        return Duration.ofMillis(challengeTimeoutMs);
    }

    /**
     * 계정 잠금 시간을 Duration으로 반환
     */
    public Duration getAccountLockoutDuration() {
        return Duration.ofMillis(accountLockoutDurationMs);
    }

    /**
     * 디바이스 기억 기간을 Duration으로 반환
     */
    public Duration getDeviceRememberDuration() {
        return Duration.ofMillis(deviceRememberDurationMs);
    }

    /**
     * OTP 토큰 유효시간을 Duration으로 반환
     */
    public Duration getOtpTokenValidity() {
        return Duration.ofSeconds(otpTokenValiditySeconds);
    }

    /**
     * State Machine 타임아웃을 Duration으로 반환
     */
    public Duration getStateMachineTimeout() {
        return Duration.ofMillis(stateMachineTimeoutMs);
    }

    /**
     * 세션이 만료되었는지 확인
     * @param lastActivityTime 마지막 활동 시간 (Instant 또는 long)
     * @return true: 만료됨, false: 유효함
     */
    public boolean isSessionExpired(java.time.Instant lastActivityTime) {
        return java.time.Instant.now().isAfter(lastActivityTime.plusMillis(sessionTimeoutMs));
    }

    /**
     * 세션이 만료되었는지 확인 (long 타임스탬프용)
     * @param lastActivityTimeMs 마지막 활동 시간 (밀리초)
     * @return true: 만료됨, false: 유효함
     */
    public boolean isSessionExpired(long lastActivityTimeMs) {
        return (System.currentTimeMillis() - lastActivityTimeMs) > sessionTimeoutMs;
    }

    /**
     * 챌린지가 만료되었는지 확인
     * @param challengeStartTime 챌린지 시작 시간 (Instant)
     * @return true: 만료됨, false: 유효함
     */
    public boolean isChallengeExpired(java.time.Instant challengeStartTime) {
        return java.time.Instant.now().isAfter(challengeStartTime.plusMillis(challengeTimeoutMs));
    }

    /**
     * 챌린지가 만료되었는지 확인 (long 타임스탬프용)
     * @param challengeStartTimeMs 챌린지 시작 시간 (밀리초)
     * @return true: 만료됨, false: 유효함
     */
    public boolean isChallengeExpired(long challengeStartTimeMs) {
        return (System.currentTimeMillis() - challengeStartTimeMs) > challengeTimeoutMs;
    }

    /**
     * 세션 갱신이 필요한지 확인
     * @param lastRefreshTime 마지막 갱신 시간 (Instant)
     * @return true: 갱신 필요, false: 갱신 불필요
     */
    public boolean needsSessionRefresh(java.time.Instant lastRefreshTime) {
        return java.time.Instant.now().isAfter(lastRefreshTime.plusMillis(sessionRefreshIntervalMs));
    }

    /**
     * 세션 만료 시간 계산 (Instant 기준)
     * @param lastActivityTime 마지막 활동 시간
     * @return 세션 만료 시간 (Instant)
     */
    public java.time.Instant calculateSessionExpiry(java.time.Instant lastActivityTime) {
        return lastActivityTime.plusMillis(sessionTimeoutMs);
    }

    /**
     * 세션 만료 시간 계산 (long 타임스탬프 기준)
     * @param lastActivityTimeMs 마지막 활동 시간 (밀리초)
     * @return 세션 만료 시간 (밀리초)
     */
    public long calculateSessionExpiry(long lastActivityTimeMs) {
        return lastActivityTimeMs + sessionTimeoutMs;
    }

    /**
     * 챌린지 만료 시간 계산 (Instant 기준)
     * @param challengeStartTime 챌린지 시작 시간
     * @return 챌린지 만료 시간 (Instant)
     */
    public java.time.Instant calculateChallengeExpiry(java.time.Instant challengeStartTime) {
        return challengeStartTime.plusMillis(challengeTimeoutMs);
    }

    /**
     * 재시도 허용 여부 확인
     * @param currentAttempts 현재 시도 횟수
     * @return true: 재시도 가능, false: 재시도 불가
     */
    public boolean isRetryAllowed(int currentAttempts) {
        return currentAttempts < maxRetryAttempts;
    }

    /**
     * 세션 갱신이 필요한지 확인
     * @param lastRefreshTime 마지막 갱신 시간
     * @return true: 갱신 필요, false: 갱신 불필요
     */
    public boolean needsSessionRefresh(long lastRefreshTime) {
        return (System.currentTimeMillis() - lastRefreshTime) > sessionRefreshIntervalMs;
    }

    /**
     * SMS 재전송 가능한지 확인
     * @param lastSentTime 마지막 전송 시간
     * @return true: 재전송 가능, false: 재전송 불가
     */
    public boolean canResendSms(long lastSentTime) {
        return (System.currentTimeMillis() - lastSentTime) > (smsResendIntervalSeconds * 1000L);
    }

    /**
     * 이메일 재전송 가능한지 확인
     * @param lastSentTime 마지막 전송 시간
     * @return true: 재전송 가능, false: 재전송 불가
     */
    public boolean canResendEmail(long lastSentTime) {
        return (System.currentTimeMillis() - lastSentTime) > (emailResendIntervalSeconds * 1000L);
    }

    /**
     * 설정 유효성 검증
     * @throws IllegalStateException 잘못된 설정이 있을 경우
     */
    public void validate() {
        if (sessionTimeoutMs <= 0) {
            throw new IllegalStateException("Session timeout must be positive");
        }

        if (challengeTimeoutMs <= 0) {
            throw new IllegalStateException("Challenge timeout must be positive");
        }

        if (challengeTimeoutMs > sessionTimeoutMs) {
            throw new IllegalStateException("Challenge timeout cannot be greater than session timeout");
        }

        if (maxRetryAttempts <= 0) {
            throw new IllegalStateException("Max retry attempts must be positive");
        }

        if (otpTokenValiditySeconds <= 0) {
            throw new IllegalStateException("OTP token validity must be positive");
        }

        if (otpTokenLength < 4 || otpTokenLength > 12) {
            throw new IllegalStateException("OTP token length must be between 4 and 12");
        }

        if (stateMachinePoolSize <= 0) {
            throw new IllegalStateException("State machine pool size must be positive");
        }
    }

    /**
     * 디버그용 설정 정보 출력
     */
    public String getDebugInfo() {
        return String.format("""
            MfaSettings Debug Info:
            - Session Timeout: %d ms (%s)
            - Challenge Timeout: %d ms (%s)
            - Max Retry Attempts: %d
            - OTP Validity: %d seconds
            - State Machine Pool Size: %d
            - Circuit Breaker Threshold: %d
            - Detailed Logging: %s
            - Metrics Enabled: %s
            - Audit Logging: %s
            """,
                sessionTimeoutMs, getSessionTimeout(),
                challengeTimeoutMs, getChallengeTimeout(),
                maxRetryAttempts,
                otpTokenValiditySeconds,
                stateMachinePoolSize,
                circuitBreakerFailureThreshold,
                detailedLoggingEnabled,
                metricsEnabled,
                auditLoggingEnabled
        );
    }
}

/**
 * SMS 팩터 설정
 */
@Getter
@Setter
class SmsFactorSettings {
    private String provider = "default";
    private String templateId = "mfa_sms_template";
    private int maxDailyAttempts = 10;
    private boolean enabled = true;
}

/**
 * 이메일 팩터 설정
 */
@Getter
@Setter
class EmailFactorSettings {
    private String fromAddress = "noreply@company.com";
    private String templateId = "mfa_email_template";
    private int maxDailyAttempts = 5;
    private boolean enabled = true;
}

/**
 * HTTP Session Repository 설정
 */
@Getter
@Setter
class HttpSessionSettings {
    private boolean enabled = true;
    private boolean createSessionIfNotExists = true;
    private String sessionAttributeName = "MFA_SESSION_ID";
}

/**
 * Redis Repository 설정
 */
@Getter
@Setter
class RedisSettings {
    private boolean enabled = true;
    private String keyPrefix = "mfa:session:";
    private String cookieName = "MFA_SID";
    private boolean secureCookie = true;
    private boolean httpOnlyCookie = true;
    private String sameSite = "Strict";
    private int connectionTimeout = 3000;
    private int maxRetries = 3;
}

/**
 * Memory Repository 설정
 */
@Getter
@Setter
class MemorySettings {
    private boolean enabled = true;
    private int cleanupIntervalMinutes = 5;
    private int maxSessions = 10000;
    private boolean enableMetrics = true;
}