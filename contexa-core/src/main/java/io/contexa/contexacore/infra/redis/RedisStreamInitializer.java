package io.contexa.contexacore.infra.redis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Redis Stream 초기화
 * 
 * 애플리케이션 시작 시 필요한 Redis Stream과 Consumer Group을 자동으로 생성합니다.
 */
@Component
public class RedisStreamInitializer implements CommandLineRunner {
    
    private static final Logger logger = LoggerFactory.getLogger(RedisStreamInitializer.class);
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;
    
    private static final String STREAM_KEY = "security-events-stream";
    private static final String CONSUMER_GROUP = "security-plane-consumers";
    
    @Override
    public void run(String... args) {
        try {
            initializeRedisStream();
        } catch (Exception e) {
            logger.error("Error initializing Redis streams", e);
        }
    }
    
    private void initializeRedisStream() {
        try {
            // Stream이 존재하지 않으면 생성
            Boolean hasKey = redisTemplate.hasKey(STREAM_KEY);
            if (Boolean.FALSE.equals(hasKey)) {
                logger.info("Creating Redis stream: {}", STREAM_KEY);
                // 더미 데이터를 추가하여 스트림 생성
                redisTemplate.opsForStream().add(STREAM_KEY, 
                    java.util.Collections.singletonMap("init", "true"));
            }
            
            // Consumer Group 생성 시도
            try {
                redisTemplate.opsForStream().createGroup(STREAM_KEY, CONSUMER_GROUP);
                logger.info("Created consumer group '{}' for stream '{}'", CONSUMER_GROUP, STREAM_KEY);
            } catch (Exception e) {
                // 이미 존재하는 경우 무시
                if (e.getMessage() != null && e.getMessage().contains("BUSYGROUP")) {
                    logger.debug("Consumer group '{}' already exists for stream '{}'", CONSUMER_GROUP, STREAM_KEY);
                } else {
                    logger.warn("Could not create consumer group: {}", e.getMessage());
                }
            }
            
            // 추가 스트림들도 초기화
            initializeAdditionalStreams();
            
        } catch (Exception e) {
            logger.error("Failed to initialize Redis stream", e);
        }
    }
    
    private void initializeAdditionalStreams() {
        // 다른 필요한 스트림들도 초기화
        String[] additionalStreams = {
            "threat-indicators-stream",
            "security-actions-stream",
            "approval-requests-stream"
        };
        
        for (String streamKey : additionalStreams) {
            try {
                Boolean hasKey = redisTemplate.hasKey(streamKey);
                if (Boolean.FALSE.equals(hasKey)) {
                    logger.info("Creating Redis stream: {}", streamKey);
                    redisTemplate.opsForStream().add(streamKey, 
                        java.util.Collections.singletonMap("init", "true"));
                }
                
                // Consumer group 생성
                try {
                    redisTemplate.opsForStream().createGroup(streamKey, CONSUMER_GROUP);
                    logger.info("Created consumer group '{}' for stream '{}'", CONSUMER_GROUP, streamKey);
                } catch (Exception e) {
                    if (e.getMessage() != null && e.getMessage().contains("BUSYGROUP")) {
                        logger.debug("Consumer group '{}' already exists for stream '{}'", CONSUMER_GROUP, streamKey);
                    }
                }
            } catch (Exception e) {
                logger.warn("Failed to initialize stream {}: {}", streamKey, e.getMessage());
            }
        }
    }
}