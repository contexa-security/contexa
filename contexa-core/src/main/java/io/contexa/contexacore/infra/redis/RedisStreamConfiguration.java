package io.contexa.contexacore.infra.redis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.stream.StreamMessageListenerContainer;

@Configuration
public class RedisStreamConfiguration {

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

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