package io.contexa.contexaidentity.security.utils;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.properties.MfaSettings;
import lombok.experimental.UtilityClass;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;


@UtilityClass
public class MfaTimeUtils {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;
    private static final DateTimeFormatter DISPLAY_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    

    
    public static Instant calculateSessionExpiry(FactorContext context, MfaSettings mfaSettings) {
        return context.getLastActivityTimestamp().plusMillis(mfaSettings.getSessionTimeoutMs());
    }

    
    public static long calculateSessionExpiryMs(FactorContext context, MfaSettings mfaSettings) {
        return calculateSessionExpiry(context, mfaSettings).toEpochMilli();
    }

    
    public static boolean isSessionExpired(FactorContext context, MfaSettings mfaSettings) {
        return mfaSettings.isSessionExpired(context.getLastActivityTimestamp());
    }

    
    public static boolean needsSessionRefresh(FactorContext context, MfaSettings mfaSettings) {
        return mfaSettings.needsSessionRefresh(context.getLastActivityTimestamp());
    }

    

    
    public static Instant calculateChallengeExpiry(Instant challengeStartTime, MfaSettings mfaSettings) {
        return challengeStartTime.plusMillis(mfaSettings.getChallengeTimeoutMs());
    }

    
    public static boolean isChallengeExpired(Instant challengeStartTime, MfaSettings mfaSettings) {
        return mfaSettings.isChallengeExpired(challengeStartTime);
    }

    
    public static boolean isChallengeExpired(FactorContext context, MfaSettings mfaSettings) {
        Object challengeTime = context.getAttribute(io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes.Timestamps.CHALLENGE_INITIATED_AT);
        if (challengeTime instanceof Long challengeTimeMs) {
            return mfaSettings.isChallengeExpired(challengeTimeMs);
        } else if (challengeTime instanceof Instant challengeInstant) {
            return mfaSettings.isChallengeExpired(challengeInstant);
        }
        return false; 
    }

    

    
    public static boolean canResendSms(Instant lastSentTime, MfaSettings mfaSettings) {
        Duration elapsed = Duration.between(lastSentTime, Instant.now());
        return elapsed.getSeconds() >= mfaSettings.getSmsResendIntervalSeconds();
    }

    
    public static boolean canResendEmail(Instant lastSentTime, MfaSettings mfaSettings) {
        Duration elapsed = Duration.between(lastSentTime, Instant.now());
        return elapsed.getSeconds() >= mfaSettings.getEmailResendIntervalSeconds();
    }

    

    
    public static Duration getRemainingSessionTime(FactorContext context, MfaSettings mfaSettings) {
        Instant expiryTime = calculateSessionExpiry(context, mfaSettings);
        Instant now = Instant.now();

        if (now.isAfter(expiryTime)) {
            return Duration.ZERO;
        }

        return Duration.between(now, expiryTime);
    }

    
    public static Duration getRemainingChallengeTime(Instant challengeStartTime, MfaSettings mfaSettings) {
        Instant expiryTime = calculateChallengeExpiry(challengeStartTime, mfaSettings);
        Instant now = Instant.now();

        if (now.isAfter(expiryTime)) {
            return Duration.ZERO;
        }

        return Duration.between(now, expiryTime);
    }

    

    
    public static Instant fromMillis(long timestampMs) {
        return Instant.ofEpochMilli(timestampMs);
    }

    
    public static long toMillis(Instant instant) {
        return instant.toEpochMilli();
    }

    
    public static long nowMillis() {
        return System.currentTimeMillis();
    }

    
    public static Instant nowInstant() {
        return Instant.now();
    }

    

    
    public static String toIsoString(Instant instant) {
        return instant.toString();
    }

    
    public static String toDisplayString(Instant instant) {
        return DISPLAY_FORMATTER.format(instant);
    }

    
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

    

    
    public static boolean isValidTimeRange(Instant startTime, Instant endTime) {
        return startTime != null && endTime != null && !startTime.isAfter(endTime);
    }

    
    public static boolean isWithinMaxAge(Instant timestamp, long maxAgeMs) {
        Duration age = Duration.between(timestamp, Instant.now());
        return age.toMillis() <= maxAgeMs;
    }

    
    public static boolean isFuture(Instant timestamp) {
        return timestamp.isAfter(Instant.now());
    }

    
    public static boolean isPast(Instant timestamp) {
        return timestamp.isBefore(Instant.now());
    }
}