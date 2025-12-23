package io.contexa.contexacore.infra.redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Redis Atomic Operations 유틸리티
 *
 * Redis 원자적 연산을 위한 유틸리티입니다.
 *
 * AI Native 리팩토링 (v3.1.0):
 * - setThreatScoreDirectly() 및 Lua 스크립트 제거
 * - ThreatScoreOrchestrator에서 직접 RedisTemplate 사용으로 변경
 * - 과도한 복잡성 제거 (146줄 -> 20줄)
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class RedisAtomicOperations {

    private final RedisTemplate<String, Object> redisTemplate;

    // AI Native: setThreatScoreDirectly() 및 Lua 스크립트 제거
    // - 단순 SET으로 충분하므로 ThreatScoreOrchestrator에서 직접 RedisTemplate 사용
    // - 복잡한 Lua 스크립트는 과도한 추상화
}
