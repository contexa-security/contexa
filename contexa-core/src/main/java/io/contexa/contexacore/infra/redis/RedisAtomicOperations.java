package io.contexa.contexacore.infra.redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;


@Slf4j
@RequiredArgsConstructor
public class RedisAtomicOperations {

    private final RedisTemplate<String, Object> redisTemplate;

    
    
    
}
