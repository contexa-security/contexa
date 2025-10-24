package io.contexa.contexaiam.config;

import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexacore.autonomous.event.publisher.AuthorizationEventPublisher;
import io.contexa.contexacommon.annotation.Protectable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;

/**
 * 애플리케이션 전체 설정
 */
@Configuration
@Slf4j
public class AppConfig {

    @Bean
    public AuthorizationManagerMethodInterceptor protectableAuthorizationAdvisor(
            ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager,
            AuthorizationEventPublisher authorizationEventPublisher) {

        Pointcut pointcut = new ComposablePointcut(classOrMethod());
        AuthorizationManagerMethodInterceptor interceptor = 
            new AuthorizationManagerMethodInterceptor(pointcut, protectableMethodAuthorizationManager);
        interceptor.setAuthorizationEventPublisher(authorizationEventPublisher);
        return interceptor;
    }

    private static Pointcut classOrMethod() {
        return Pointcuts.union(new AnnotationMatchingPointcut(null, Protectable.class, true),
                new AnnotationMatchingPointcut(Protectable.class, true));
    }

    @Bean
    public WebClientCustomizer webClientCustomizer() {
        // 1. ConnectionProvider 생성 (더 안정적인 create 메서드 사용)
        // "custom-ai-pool"은 풀의 이름이며, 50은 최대 커넥션 수입니다.
        ConnectionProvider provider = ConnectionProvider.create("custom-ai-pool", 50);

        // 2. 생성된 ConnectionProvider를 사용하는 HttpClient 생성
        // HttpClient.create()는 reactor.netty.http.client.HttpClient 인터페이스의 기본 정적 메서드입니다.
        HttpClient httpClient = HttpClient.create(provider)
                .responseTimeout(Duration.ofMinutes(3)); // AI 응답이 길어질 수 있으므로 타임아웃 설정

        // 3. 생성된 HttpClient를 WebClient.Builder에 적용
        return builder -> builder.clientConnector(new ReactorClientHttpConnector(httpClient));
    }
}
