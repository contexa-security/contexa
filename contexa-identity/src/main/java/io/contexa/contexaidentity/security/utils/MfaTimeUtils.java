package io.contexa.contexaidentity.security.utils;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.properties.MfaSettings;
import lombok.experimental.UtilityClass;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * MFA 시간 처리를 위한 타입 안전 유틸리티 클래스
 * - Instant와 long 간의 안전한 변환
 * - 세션 및 챌린지 타임아웃 계산
 * - 일관된 시간 처리 로직 제공
 */
@UtilityClass
public class MfaTimeUtils {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private static final DateTimeFormatter DISPLAY_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    // === 세션 관련 시간 계산 ===

    /**
     * 세션 만료 시간 계산
     * @param context Factor 컨텍스트
     * @param mfaSettings MFA 설정
     * @return 세션 만료 시간 (Instant)
     */
    public static Instant calculateSessionExpiry(FactorContext context, MfaSettings mfaSettings) {
        return context.getLastActivityTimestamp().plusMillis(mfaSettings.getSessionTimeoutMs());
    }

    /**
     * 세션 만료 시간 계산 (밀리초 반환)
     * @param context Factor 컨텍스트
     * @param mfaSettings MFA 설정
     * @return 세션 만료 시간 (밀리초)
     */
    public static long calculateSessionExpiryMs(FactorContext context, MfaSettings mfaSettings) {
        return calculateSessionExpiry(context, mfaSettings).toEpochMilli();
    }

    /**
     * 세션이 만료되었는지 확인
     * @param context Factor 컨텍스트
     * @param mfaSettings MFA 설정
     * @return true: 만료됨, false: 유효함
     */
    public static boolean isSessionExpired(FactorContext context, MfaSettings mfaSettings) {
        return mfaSettings.isSessionExpired(context.getLastActivityTimestamp());
    }

    /**
     * 세션 갱신이 필요한지 확인
     * @param context Factor 컨텍스트
     * @param mfaSettings MFA 설정
     * @return true: 갱신 필요, false: 갱신 불필요
     */
    public static boolean needsSessionRefresh(FactorContext context, MfaSettings mfaSettings) {
        return mfaSettings.needsSessionRefresh(context.getLastActivityTimestamp());
    }

    // === 챌린지 관련 시간 계산 ===

    /**
     * 챌린지 만료 시간 계산
     * @param challengeStartTime 챌린지 시작 시간
     * @param mfaSettings MFA 설정
     * @return 챌린지 만료 시간 (Instant)
     */
    public static Instant calculateChallengeExpiry(Instant challengeStartTime, MfaSettings mfaSettings) {
        return challengeStartTime.plusMillis(mfaSettings.getChallengeTimeoutMs());
    }

    /**
     * 챌린지가 만료되었는지 확인
     * @param challengeStartTime 챌린지 시작 시간
     * @param mfaSettings MFA 설정
     * @return true: 만료됨, false: 유효함
     */
    public static boolean isChallengeExpired(Instant challengeStartTime, MfaSettings mfaSettings) {
        return mfaSettings.isChallengeExpired(challengeStartTime);
    }

    /**
     * 컨텍스트에서 챌린지 만료 확인
     * @param context Factor 컨텍스트
     * @param mfaSettings MFA 설정
     * @return true: 만료됨, false: 유효함
     */
    public static boolean isChallengeExpired(FactorContext context, MfaSettings mfaSettings) {
        Object challengeTime = context.getAttribute(io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes.Timestamps.CHALLENGE_INITIATED_AT);
        if (challengeTime instanceof Long challengeTimeMs) {
            return mfaSettings.isChallengeExpired(challengeTimeMs);
        } else if (challengeTime instanceof Instant challengeInstant) {
            return mfaSettings.isChallengeExpired(challengeInstant);
        }
        return false; // 챌린지 시작 시간이 없으면 만료되지 않은 것으로 간주
    }

    // === 재전송 관련 시간 계산 ===

    /**
     * SMS 재전송 가능한지 확인
     * @param lastSentTime 마지막 전송 시간
     * @param mfaSettings MFA 설정
     * @return true: 재전송 가능, false: 재전송 불가
     */
    public static boolean canResendSms(Instant lastSentTime, MfaSettings mfaSettings) {
        Duration elapsed = Duration.between(lastSentTime, Instant.now());
        return elapsed.getSeconds() >= mfaSettings.getSmsResendIntervalSeconds();
    }

    /**
     * 이메일 재전송 가능한지 확인
     * @param lastSentTime 마지막 전송 시간
     * @param mfaSettings MFA 설정
     * @return true: 재전송 가능, false: 재전송 불가
     */
    public static boolean canResendEmail(Instant lastSentTime, MfaSettings mfaSettings) {
        Duration elapsed = Duration.between(lastSentTime, Instant.now());
        return elapsed.getSeconds() >= mfaSettings.getEmailResendIntervalSeconds();
    }

    // === 남은 시간 계산 ===

    /**
     * 세션 만료까지 남은 시간 계산
     * @param context Factor 컨텍스트
     * @param mfaSettings MFA 설정
     * @return 남은 시간 (Duration)
     */
    public static Duration getRemainingSessionTime(FactorContext context, MfaSettings mfaSettings) {
        Instant expiryTime = calculateSessionExpiry(context, mfaSettings);
        Instant now = Instant.now();

        if (now.isAfter(expiryTime)) {
            return Duration.ZERO;
        }

        return Duration.between(now, expiryTime);
    }

    /**
     * 챌린지 만료까지 남은 시간 계산
     * @param challengeStartTime 챌린지 시작 시간
     * @param mfaSettings MFA 설정
     * @return 남은 시간 (Duration)
     */
    public static Duration getRemainingChallengeTime(Instant challengeStartTime, MfaSettings mfaSettings) {
        Instant expiryTime = calculateChallengeExpiry(challengeStartTime, mfaSettings);
        Instant now = Instant.now();

        if (now.isAfter(expiryTime)) {
            return Duration.ZERO;
        }

        return Duration.between(now, expiryTime);
    }

    // === 타입 변환 유틸리티 ===

    /**
     * 밀리초를 Instant로 변환
     * @param timestampMs 밀리초 타임스탬프
     * @return Instant 객체
     */
    public static Instant fromMillis(long timestampMs) {
        return Instant.ofEpochMilli(timestampMs);
    }

    /**
     * Instant를 밀리초로 변환
     * @param instant Instant 객체
     * @return 밀리초 타임스탬프
     */
    public static long toMillis(Instant instant) {
        return instant.toEpochMilli();
    }

    /**
     * 현재 시간을 밀리초로 반환
     * @return 현재 시간 (밀리초)
     */
    public static long nowMillis() {
        return System.currentTimeMillis();
    }

    /**
     * 현재 시간을 Instant로 반환
     * @return 현재 시간 (Instant)
     */
    public static Instant nowInstant() {
        return Instant.now();
    }

    // === 포맷팅 유틸리티 ===

    /**
     * Instant를 ISO 형식 문자열로 변환
     * @param instant Instant 객체
     * @return ISO 형식 문자열
     */
    public static String toIsoString(Instant instant) {
        return instant.toString();
    }

    /**
     * Instant를 사용자 친화적 형식으로 변환
     * @param instant Instant 객체
     * @return 사용자 친화적 형식 문자열
     */
    public static String toDisplayString(Instant instant) {
        return DISPLAY_FORMATTER.format(instant);
    }

    /**
     * Duration을 사용자 친화적 형식으로 변환
     * @param duration Duration 객체
     * @return 사용자 친화적 형식 문자열 (예: "5분 30초")
     */
    public static String toDisplayString(Duration duration) {
        if (duration.isZero() || duration.isNegative()) {
            return "0초";
        }

        long totalSeconds = duration.getSeconds();
        long hours = totalSeconds / 3600;
        long minutes = (totalSeconds % 3600) / 60;
        long seconds = totalSeconds % 60;

        StringBuilder sb = new StringBuilder();

        if (hours > 0) {
            sb.append(hours).append("시간 ");
        }

        if (minutes > 0) {
            sb.append(minutes).append("분 ");
        }

        if (seconds > 0 || sb.length() == 0) {
            sb.append(seconds).append("초");
        }

        return sb.toString().trim();
    }

    // === 검증 유틸리티 ===

    /**
     * 시간 범위가 유효한지 확인
     * @param startTime 시작 시간
     * @param endTime 종료 시간
     * @return true: 유효한 범위, false: 잘못된 범위
     */
    public static boolean isValidTimeRange(Instant startTime, Instant endTime) {
        return startTime != null && endTime != null && !startTime.isAfter(endTime);
    }

    /**
     * 타임스탬프가 유효한 범위 내에 있는지 확인
     * @param timestamp 확인할 타임스탬프
     * @param maxAgeMs 최대 허용 나이 (밀리초)
     * @return true: 유효함, false: 너무 오래됨
     */
    public static boolean isWithinMaxAge(Instant timestamp, long maxAgeMs) {
        Duration age = Duration.between(timestamp, Instant.now());
        return age.toMillis() <= maxAgeMs;
    }

    /**
     * 미래 시간인지 확인
     * @param timestamp 확인할 타임스탬프
     * @return true: 미래 시간, false: 과거 또는 현재 시간
     */
    public static boolean isFuture(Instant timestamp) {
        return timestamp.isAfter(Instant.now());
    }

    /**
     * 과거 시간인지 확인
     * @param timestamp 확인할 타임스탬프
     * @return true: 과거 시간, false: 현재 또는 미래 시간
     */
    public static boolean isPast(Instant timestamp) {
        return timestamp.isBefore(Instant.now());
    }
}