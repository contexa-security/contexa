package io.contexa.contexacore.infra.redis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.stream.StreamMessageListenerContainer;

/**
 * Redis Stream Configuration
 * 
 * StreamMessageListenerContainer 빈을 제공합니다.
 */
@Configuration
public class RedisStreamConfiguration {

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    /**
     * StreamMessageListenerContainer 빈 생성
     * 
     * Redis Stream 메시지를 비동기적으로 처리하기 위한 컨테이너입니다.
     * 
     * @return StreamMessageListenerContainer 인스턴스
     */
    @Bean
    public StreamMessageListenerContainer<String, ?> streamMessageListenerContainer() {
        StreamMessageListenerContainer.StreamMessageListenerContainerOptions<String, ?> options = 
            StreamMessageListenerContainer.StreamMessageListenerContainerOptions
                .builder()
                .pollTimeout(java.time.Duration.ofSeconds(1))
                .targetType(String.class)
                .build();

        return StreamMessageListenerContainer.create(redisConnectionFactory, options);
    }
}