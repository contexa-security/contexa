package io.contexa.contexacore.infra.redis;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Redis Atomic Operations 유틸리티
 * 
 * Trust Score 업데이트와 같은 원자적 연산을 위한 Lua 스크립트 기반 유틸리티입니다.
 * Race condition을 방지하고 데이터 일관성을 보장합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class RedisAtomicOperations {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${threat.score.initial:0.3}")
    private double defaultThreatScore;

    @Value("${threat.score.decay.rate:0.05}")
    private double threatScoreDecayRate;
    
    /**
     * Threat Score와 User Context 동시 업데이트 스크립트 (시간 기반 감쇠 적용)
     * - Threat Score 업데이트 (시간 기반 감쇠 적용)
     * - User Context 업데이트
     * - 마지막 업데이트 시간 기록
     * - 모든 작업이 원자적으로 수행
     *
     * 개선 사항:
     * - 업데이트 횟수 기반 → 시간 기반 감쇠로 변경
     * - lastUpdateTime 추적 추가
     * - adjustment 범위 검증 추가 (-1.0 ~ 1.0)
     */
    private static final String UPDATE_THREAT_AND_CONTEXT_SCRIPT =
        "local threatKey = KEYS[1] " +
        "local authKey = KEYS[2] " +
        "local contextKey = KEYS[3] " +
        "local lastUpdateKey = KEYS[4] " +  // 마지막 업데이트 시간 키 추가
        "local adjustment = tonumber(ARGV[1]) " +
        "local ttlSeconds = tonumber(ARGV[2]) " +
        "local defaultScore = tonumber(ARGV[3]) " +
        "local contextJson = ARGV[4] " +
        "local hourlyDecayRate = tonumber(ARGV[5]) " +  // 시간당 감쇠율
        "local currentTimestamp = tonumber(ARGV[6]) " +  // 현재 Unix timestamp (초)
        // adjustment 범위 검증 (-1.0 ~ 1.0)
        "local validatedAdjustment = math.max(-1.0, math.min(1.0, adjustment)) " +
        // 현재 Threat Score 조회
        "local currentStr = redis.call('get', threatKey) " +
        "local current = defaultScore " +
        "if currentStr then " +
        "  local parsed = tonumber(currentStr) " +
        "  if parsed then current = parsed end " +
        "end " +
        // 마지막 업데이트 시간 조회
        "local lastUpdateStr = redis.call('get', lastUpdateKey) " +
        "local lastUpdate = 0 " +
        "if lastUpdateStr then " +
        "  local parsed = tonumber(lastUpdateStr) " +
        "  if parsed then lastUpdate = parsed end " +
        "end " +
        // 경과 시간 계산 (초 → 시간)
        "local elapsedSeconds = currentTimestamp - lastUpdate " +
        "local hoursElapsed = elapsedSeconds / 3600.0 " +
        // 시간 기반 감쇠 적용 (지수 감쇠: score * (1 - rate)^hours)
        "local decayFactor = math.pow(1.0 - hourlyDecayRate, hoursElapsed) " +
        "local decayed = current * decayFactor " +
        // 새로운 점수 계산 (감쇠 후 adjustment 적용, 범위 0.0-1.0)
        "local new = math.max(0.0, math.min(1.0, decayed + validatedAdjustment)) " +
        // Redis 업데이트
        "redis.call('setex', threatKey, ttlSeconds, tostring(new)) " +
        "redis.call('setex', lastUpdateKey, ttlSeconds, tostring(currentTimestamp)) " +  // 마지막 업데이트 시간 저장
        "redis.call('del', authKey) " +
        "if contextJson and contextJson ~= '' then " +
        "  redis.call('setex', contextKey, ttlSeconds, contextJson) " +
        "end " +
        "return tostring(new)";
    
    /**
     * Threat Score와 User Context 원자적 동시 업데이트
     *
     * @param userId 사용자 ID
     * @param adjustment Threat Score 조정값
     * @param userContextJson User Context JSON
     * @param ttlDays TTL (일 단위)
     * @return 업데이트된 새로운 threat score
     */
    public double updateThreatScoreWithContext(String userId, double adjustment,
                                                String userContextJson, int ttlDays) {
        try {
            log.debug("UPDATE_THREAT_AND_CONTEXT_SCRIPT length: {}", UPDATE_THREAT_AND_CONTEXT_SCRIPT.length());
            log.debug("Script content preview: {}", UPDATE_THREAT_AND_CONTEXT_SCRIPT.substring(0, Math.min(200, UPDATE_THREAT_AND_CONTEXT_SCRIPT.length())));

            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            String authCacheKey = ZeroTrustRedisKeys.userAuthorities(userId);
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            String lastUpdateKey = ZeroTrustRedisKeys.threatScore(userId) + ":lastUpdate";  // 마지막 업데이트 시간 키

            // KEYS 배열에 lastUpdateKey 추가
            List<String> keys = Arrays.asList(threatScoreKey, authCacheKey, contextKey, lastUpdateKey);

            // 현재 Unix timestamp (초 단위)
            long currentTimestamp = System.currentTimeMillis() / 1000;

            Object[] args = new Object[] {
                String.valueOf(adjustment),
                String.valueOf(TimeUnit.DAYS.toSeconds(ttlDays)),
                String.valueOf(defaultThreatScore),  // 설정 가능한 초기값
                userContextJson != null ? userContextJson : "",
                String.valueOf(threatScoreDecayRate),  // 시간당 감쇠율
                String.valueOf(currentTimestamp)  // 현재 timestamp 추가
            };

            String result = redisTemplate.execute(
                (connection) -> {
                    byte[] scriptBytes = UPDATE_THREAT_AND_CONTEXT_SCRIPT.getBytes();
                    List<byte[]> keyBytes = keys.stream()
                        .map(String::getBytes)
                        .toList();
                    byte[][] argBytes = new byte[args.length][];
                    for (int i = 0; i < args.length; i++) {
                        argBytes[i] = String.valueOf(args[i]).getBytes();
                    }

                    Object rawResult = connection.eval(scriptBytes,
                        ReturnType.VALUE,
                        keyBytes.size(),
                        Stream.concat(
                            keyBytes.stream(),
                            Arrays.stream(argBytes)
                        ).toArray(byte[][]::new)
                    );

                    if (rawResult instanceof byte[]) {
                        return new String((byte[]) rawResult);
                    }
                    return null;
                },
                true
            );

            if (result != null) {
                double newScore = Double.parseDouble(result);

                log.info("Threat score and context atomically updated for user {}: new score = {}",
                    userId, newScore);

                return newScore;
            }

            return defaultThreatScore; // 설정 가능한 기본값

        } catch (Exception e) {
            log.error("Error in atomic threat score and context update for user: {}", userId, e);
            return defaultThreatScore; // 설정 가능한 기본값
        }
    }

    /**
     * AI Native: Threat Score 직접 설정 Lua 스크립트 (시간 감쇠 없음)
     *
     * AI Native 원칙:
     * - LLM이 반환한 riskScore(0.0~1.0)를 그대로 저장
     * - 시간 감쇠(decay) 완전 제거
     * - 누적(adjustment) 방식이 아닌 직접 설정(SET) 방식
     * - LLM 판단을 100% 신뢰
     *
     * 기존 방식의 문제점:
     * - 시간 감쇠로 24시간 후 71% 감소
     * - 누적 방식으로 ±0.15 제한
     * - LLM이 CRITICAL(0.95) 반환해도 0.15만 반영
     *
     * 새로운 방식:
     * - LLM이 CRITICAL(0.95) 반환 → Redis에 0.95 그대로 저장
     * - 세션별 독립적 판정 (이전 점수와 무관)
     */
    private static final String SET_THREAT_SCORE_DIRECTLY_SCRIPT =
        "local threatKey = KEYS[1] " +
        "local authKey = KEYS[2] " +
        "local contextKey = KEYS[3] " +
        "local riskScore = tonumber(ARGV[1]) " +
        "local ttlSeconds = tonumber(ARGV[2]) " +
        "local contextJson = ARGV[3] " +
        // riskScore 범위 검증 (0.0 ~ 1.0)
        "local validatedScore = math.max(0.0, math.min(1.0, riskScore)) " +
        // Redis 직접 설정 (시간 감쇠 없음, 누적 없음)
        "redis.call('setex', threatKey, ttlSeconds, tostring(validatedScore)) " +
        // 권한 캐시 무효화 (보안 정책 재평가 강제)
        "redis.call('del', authKey) " +
        // User Context 저장 (있을 경우)
        "if contextJson and contextJson ~= '' then " +
        "  redis.call('setex', contextKey, ttlSeconds, contextJson) " +
        "end " +
        "return tostring(validatedScore)";

    /**
     * AI Native: Threat Score 직접 설정 (시간 감쇠 없음)
     *
     * LLM이 반환한 riskScore를 그대로 Redis에 저장합니다.
     * 기존 누적 방식이 아닌 직접 설정 방식으로, LLM 판단을 100% 신뢰합니다.
     *
     * 용도:
     * - Cold Path에서 LLM 분석 완료 후 호출
     * - ALLOW/BLOCK/STEP_UP 판정의 근거가 되는 riskScore 저장
     *
     * @param userId 사용자 ID
     * @param riskScore LLM이 반환한 위험 점수 (0.0 ~ 1.0, 가공 없이 그대로 사용)
     * @param userContextJson User Context JSON (감사 로그용)
     * @param ttlDays TTL (일 단위)
     * @return 저장된 threat score (검증 후)
     */
    public double setThreatScoreDirectly(String userId, double riskScore,
                                          String userContextJson, int ttlDays) {
        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            String authCacheKey = ZeroTrustRedisKeys.userAuthorities(userId);
            String contextKey = ZeroTrustRedisKeys.userContext(userId);

            List<String> keys = Arrays.asList(threatScoreKey, authCacheKey, contextKey);

            Object[] args = new Object[] {
                String.valueOf(riskScore),
                String.valueOf(TimeUnit.DAYS.toSeconds(ttlDays)),
                userContextJson != null ? userContextJson : ""
            };

            String result = redisTemplate.execute(
                (connection) -> {
                    byte[] scriptBytes = SET_THREAT_SCORE_DIRECTLY_SCRIPT.getBytes();
                    List<byte[]> keyBytes = keys.stream()
                        .map(String::getBytes)
                        .toList();
                    byte[][] argBytes = new byte[args.length][];
                    for (int i = 0; i < args.length; i++) {
                        argBytes[i] = String.valueOf(args[i]).getBytes();
                    }

                    Object rawResult = connection.eval(scriptBytes,
                        ReturnType.VALUE,
                        keyBytes.size(),
                        Stream.concat(
                            keyBytes.stream(),
                            Arrays.stream(argBytes)
                        ).toArray(byte[][]::new)
                    );

                    if (rawResult instanceof byte[]) {
                        return new String((byte[]) rawResult);
                    }
                    return null;
                },
                true
            );

            if (result != null) {
                double savedScore = Double.parseDouble(result);

                log.info("[AI Native] Threat score directly set for user {}: riskScore={} → saved={}",
                    userId, String.format("%.3f", riskScore), String.format("%.3f", savedScore));

                return savedScore;
            }

            return riskScore; // Lua 실행 실패 시 입력값 반환

        } catch (Exception e) {
            log.error("[AI Native] Error setting threat score directly for user: {}", userId, e);
            return riskScore; // 예외 시 입력값 반환
        }
    }
}