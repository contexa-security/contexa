package io.contexa.autoconfigure.iam;

import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.publisher.AuthorizationEventPublisher;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;

/**
 * IAM 인프라 AutoConfiguration
 *
 * <p>
 * Querydsl, WebClient 등 IAM 기본 인프라 설정을 제공합니다.
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>JPAQueryFactory - Querydsl JPA 쿼리 팩토리</li>
 *   <li>AuthorizationManagerMethodInterceptor - @Protectable 메서드 인터셉터</li>
 *   <li>WebClientCustomizer - AI 클라이언트용 WebClient 커스터마이저</li>
 * </ul>
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
public class IamInfrastructureAutoConfiguration {

    /**
     * Querydsl JPA 쿼리 팩토리
     *
     * <p>
     * Querydsl을 사용한 타입 안전 JPA 쿼리를 생성하기 위한 팩토리입니다.
     * </p>
     *
     * @param entityManager JPA EntityManager
     * @return JPAQueryFactory
     */
    @Bean
    @ConditionalOnMissingBean
    public JPAQueryFactory jpaQueryFactory(EntityManager entityManager) {
        log.info("JPAQueryFactory 빈 등록");
        return new JPAQueryFactory(entityManager);
    }

    /**
     * @Protectable 어노테이션 메서드 인터셉터
     *
     * <p>
     * @Protectable 어노테이션이 적용된 메서드에 대한 XACML 기반 인가 처리를 수행합니다.
     * meterRegistryPostProcessor 빈이 존재할 때만 활성화됩니다.
     * </p>
     *
     * @param protectableMethodAuthorizationManager XACML 기반 메서드 인가 관리자
     * @param authorizationEventPublisher 인가 이벤트 발행자
     * @return AuthorizationManagerMethodInterceptor
     */
    @Bean
    @ConditionalOnBean(name = "meterRegistryPostProcessor")
    @ConditionalOnMissingBean
    public AuthorizationManagerMethodInterceptor protectableAuthorizationAdvisor(
            ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager,
            AuthorizationEventPublisher authorizationEventPublisher) {

        log.info("AuthorizationManagerMethodInterceptor 빈 등록 (@Protectable 메서드 인터셉터)");

        Pointcut pointcut = new ComposablePointcut(classOrMethod());
        AuthorizationManagerMethodInterceptor interceptor =
            new AuthorizationManagerMethodInterceptor(pointcut, protectableMethodAuthorizationManager);
        interceptor.setAuthorizationEventPublisher(authorizationEventPublisher);
        return interceptor;
    }

    /**
     * @Protectable 어노테이션 포인트컷 생성
     *
     * <p>
     * 클래스 레벨 또는 메서드 레벨에 @Protectable 어노테이션이 적용된 경우를 매칭합니다.
     * </p>
     *
     * @return Pointcut
     */
    private static Pointcut classOrMethod() {
        return Pointcuts.union(
            new AnnotationMatchingPointcut(null, Protectable.class, true),
            new AnnotationMatchingPointcut(Protectable.class, true)
        );
    }

    /**
     * AI 클라이언트용 WebClient 커스터마이저
     *
     * <p>
     * AI API 호출에 최적화된 WebClient 설정을 제공합니다:
     * </p>
     * <ul>
     *   <li>커넥션 풀: 최대 50개 커넥션</li>
     *   <li>응답 타임아웃: 3분 (AI 응답 대기 시간 고려)</li>
     * </ul>
     *
     * @return WebClientCustomizer
     */
    @Bean
    @ConditionalOnMissingBean
    public WebClientCustomizer webClientCustomizer() {
        log.info("WebClientCustomizer 빈 등록 (AI 클라이언트용 최적화 설정)");

        // ConnectionProvider 생성 (최대 50개 커넥션)
        ConnectionProvider provider = ConnectionProvider.create("custom-ai-pool", 50);

        // HttpClient 생성 (3분 타임아웃)
        HttpClient httpClient = HttpClient.create(provider)
                .responseTimeout(Duration.ofMinutes(3));

        // WebClient.Builder에 적용
        return builder -> builder.clientConnector(new ReactorClientHttpConnector(httpClient));
    }
}
