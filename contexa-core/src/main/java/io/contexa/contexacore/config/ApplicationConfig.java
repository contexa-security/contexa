package io.contexa.contexacore.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.config.jackson.CustomJacksonModule;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Primary;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.support.ExecutorSubscribableChannel;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * 애플리케이션 전체 설정
 */
@Slf4j
@EnableConfigurationProperties({TieredLLMProperties.class, ModelProviderProperties.class, SecurityMappingProperties.class})
@Configuration
@EnableAspectJAutoProxy(proxyTargetClass = true, exposeProxy = true)
@EnableScheduling
@EnableAsync
public class ApplicationConfig {

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // JSR310 모듈 등록 (LocalDateTime 직렬화 지원)
        mapper.registerModule(new JavaTimeModule());

        // Custom 모듈 등록 (Duration 등 커스텀 직렬화/역직렬화 지원)
        mapper.registerModule(new CustomJacksonModule());

        // 기본 설정
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        log.info("Jackson ObjectMapper 설정 완료 (JSR310 및 Custom 모듈 등록)");
        return mapper;
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

}
