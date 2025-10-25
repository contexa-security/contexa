package io.contexa.contexacore.plane.service;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

/**
 * 공격 모드 히스테리시스 관리자
 *
 * Dual Threshold Hysteresis를 사용하여 공격 모드 전환 시
 * 플래핑(Flapping)을 방지합니다.
 *
 * 핵심 기능:
 * 1. Dual Threshold (진입 임계값 > 해제 임계값)
 * 2. 최소 지속 시간 (15분)
 * 3. Rate Limiting (5분당 최대 3회 전환)
 *
 * 외부기관 1 피드백 반영:
 * - "공격 모드 히스테리시스가 필요합니다"
 * - Dual Threshold + 최소 지속 시간 + Rate Limiting
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
@Service
public class AttackModeHysteresisManager {

    @Autowired
    @Qualifier("generalRedisTemplate")
    private RedisTemplate<String, Object> redisTemplate;

    // ===== 설정값 (application.yml에서 주입) =====

    /**
     * SUSPECTED 모드 진입 임계값 (기본: 0.7)
     * 위험 점수가 이 값을 초과하면 SUSPECTED로 전환
     */
    @Value("${attack.mode.suspected.enter.threshold:0.7}")
    private double suspectedEnterThreshold;

    /**
     * SUSPECTED 모드 해제 임계값 (기본: 0.5)
     * 위험 점수가 이 값 미만으로 떨어지면 NORMAL로 전환
     */
    @Value("${attack.mode.suspected.exit.threshold:0.5}")
    private double suspectedExitThreshold;

    /**
     * CONFIRMED 모드 진입 임계값 (기본: 0.85)
     * 위험 점수가 이 값을 초과하면 CONFIRMED로 전환
     */
    @Value("${attack.mode.confirmed.enter.threshold:0.85}")
    private double confirmedEnterThreshold;

    /**
     * CONFIRMED 모드 해제 임계값 (기본: 0.6)
     * 위험 점수가 이 값 미만으로 떨어지면 SUSPECTED로 전환
     */
    @Value("${attack.mode.confirmed.exit.threshold:0.6}")
    private double confirmedExitThreshold;

    /**
     * 최소 지속 시간 (분, 기본: 15분)
     * 모드 전환 후 이 시간 동안은 재전환 불가
     */
    @Value("${attack.mode.min.duration.minutes:15}")
    private int minDurationMinutes;

    /**
     * Rate Limiting 윈도우 (분, 기본: 5분)
     */
    @Value("${attack.mode.rate.limit.window.minutes:5}")
    private int rateLimitWindowMinutes;

    /**
     * Rate Limiting 최대 전환 횟수 (기본: 3회)
     */
    @Value("${attack.mode.rate.limit.max.transitions:3}")
    private int rateLimitMaxTransitions;

    // ===== Public Methods =====

    /**
     * 위험 점수 기반 공격 모드 업데이트
     *
     * @param userId 사용자 ID
     * @param riskScore 위험 점수 (0.0~1.0)
     * @return AttackModeState (현재 모드 및 전환 정보)
     */
    public AttackModeState updateAttackMode(String userId, double riskScore) {
        // 1. 현재 상태 조회
        AttackModeState currentState = getAttackModeState(userId);

        // 2. 최소 지속 시간 체크
        if (!canTransition(currentState)) {
            log.debug("[AttackModeHysteresis] Minimum duration not met for user {}, keeping mode {}",
                    userId, currentState.getMode());
            return currentState;
        }

        // 3. Rate Limiting 체크
        if (!checkRateLimit(userId)) {
            log.warn("[AttackModeHysteresis] Rate limit exceeded for user {}, keeping mode {}",
                    userId, currentState.getMode());
            return currentState;
        }

        // 4. Dual Threshold Hysteresis 적용
        AttackMode newMode = calculateNewMode(currentState.getMode(), riskScore);

        // 5. 모드 변경 여부 확인
        if (newMode != currentState.getMode()) {
            // 모드 전환
            AttackModeState newState = AttackModeState.builder()
                    .mode(newMode)
                    .riskScore(riskScore)
                    .enteredAt(LocalDateTime.now())
                    .previousMode(currentState.getMode())
                    .transitionCount(currentState.getTransitionCount() + 1)
                    .build();

            saveAttackModeState(userId, newState);
            recordTransition(userId, currentState.getMode(), newMode);

            log.info("[AttackModeHysteresis] Mode transition for user {}: {} → {} (risk: {})",
                    userId, currentState.getMode(), newMode, String.format("%.3f", riskScore));

            return newState;
        } else {
            // 모드 유지 (위험 점수만 업데이트)
            AttackModeState updatedState = AttackModeState.builder()
                    .mode(currentState.getMode())
                    .riskScore(riskScore)
                    .enteredAt(currentState.getEnteredAt())
                    .previousMode(currentState.getPreviousMode())
                    .transitionCount(currentState.getTransitionCount())
                    .build();

            saveAttackModeState(userId, updatedState);

            return updatedState;
        }
    }

    /**
     * 사용자의 현재 공격 모드 상태 조회
     *
     * @param userId 사용자 ID
     * @return AttackModeState
     */
    public AttackModeState getAttackModeState(String userId) {
        String key = buildStateKey(userId);

        @SuppressWarnings("unchecked")
        AttackModeState state = (AttackModeState) redisTemplate.opsForValue().get(key);

        if (state == null) {
            // 초기 상태 생성
            state = AttackModeState.builder()
                    .mode(AttackMode.NORMAL)
                    .riskScore(0.0)
                    .enteredAt(LocalDateTime.now())
                    .previousMode(AttackMode.NORMAL)
                    .transitionCount(0)
                    .build();
        }

        return state;
    }

    /**
     * 공격 모드 강제 리셋 (테스트용)
     */
    public void resetAttackMode(String userId) {
        String stateKey = buildStateKey(userId);
        String transitionKey = buildTransitionKey(userId);

        redisTemplate.delete(stateKey);
        redisTemplate.delete(transitionKey);

        log.info("[AttackModeHysteresis] Reset attack mode for user {}", userId);
    }

    // ===== Private Methods =====

    /**
     * Dual Threshold Hysteresis 기반 새 모드 계산
     */
    private AttackMode calculateNewMode(AttackMode currentMode, double riskScore) {
        switch (currentMode) {
            case NORMAL:
                // NORMAL → SUSPECTED
                if (riskScore > suspectedEnterThreshold) {
                    return AttackMode.SUSPECTED;
                }
                return AttackMode.NORMAL;

            case SUSPECTED:
                // SUSPECTED → CONFIRMED
                if (riskScore > confirmedEnterThreshold) {
                    return AttackMode.CONFIRMED;
                }
                // SUSPECTED → NORMAL
                if (riskScore < suspectedExitThreshold) {
                    return AttackMode.NORMAL;
                }
                return AttackMode.SUSPECTED;

            case CONFIRMED:
                // CONFIRMED → SUSPECTED
                if (riskScore < confirmedExitThreshold) {
                    return AttackMode.SUSPECTED;
                }
                return AttackMode.CONFIRMED;

            default:
                return AttackMode.NORMAL;
        }
    }

    /**
     * 최소 지속 시간 체크
     */
    private boolean canTransition(AttackModeState state) {
        LocalDateTime now = LocalDateTime.now();
        Duration duration = Duration.between(state.getEnteredAt(), now);

        return duration.toMinutes() >= minDurationMinutes;
    }

    /**
     * Rate Limiting 체크
     */
    private boolean checkRateLimit(String userId) {
        String key = buildTransitionKey(userId);

        Long transitionCount = redisTemplate.opsForList().size(key);

        if (transitionCount == null) {
            transitionCount = 0L;
        }

        return transitionCount < rateLimitMaxTransitions;
    }

    /**
     * 전환 기록 (Rate Limiting용)
     */
    private void recordTransition(String userId, AttackMode fromMode, AttackMode toMode) {
        String key = buildTransitionKey(userId);

        TransitionRecord record = TransitionRecord.builder()
                .fromMode(fromMode)
                .toMode(toMode)
                .timestamp(LocalDateTime.now())
                .build();

        redisTemplate.opsForList().rightPush(key, record);

        // 윈도우 시간만큼 유지
        redisTemplate.expire(key, rateLimitWindowMinutes, TimeUnit.MINUTES);
    }

    /**
     * 공격 모드 상태 저장
     */
    private void saveAttackModeState(String userId, AttackModeState state) {
        String key = buildStateKey(userId);
        redisTemplate.opsForValue().set(key, state);

        // 24시간 TTL
        redisTemplate.expire(key, 24, TimeUnit.HOURS);
    }

    /**
     * Redis 키 생성
     */
    private String buildStateKey(String userId) {
        return "attack:mode:state:" + userId;
    }

    private String buildTransitionKey(String userId) {
        return "attack:mode:transitions:" + userId;
    }

    // ===== Inner Classes =====

    /**
     * 공격 모드
     */
    public enum AttackMode {
        NORMAL,      // 정상
        SUSPECTED,   // 의심
        CONFIRMED    // 확정
    }

    /**
     * 공격 모드 상태
     */
    @Getter
    @Builder
    public static class AttackModeState implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private final AttackMode mode;           // 현재 모드
        private final double riskScore;          // 현재 위험 점수
        private final LocalDateTime enteredAt;   // 현재 모드 진입 시간
        private final AttackMode previousMode;   // 이전 모드
        private final int transitionCount;       // 전환 횟수 (세션 내)
    }

    /**
     * 전환 기록
     */
    @Getter
    @Builder
    private static class TransitionRecord implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private final AttackMode fromMode;
        private final AttackMode toMode;
        private final LocalDateTime timestamp;
    }
}
