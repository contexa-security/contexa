package io.contexa.autoconfigure.iam;

import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.ObjectProvider;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;

@Slf4j
@AutoConfiguration
@EnableCaching
public class IamInfrastructureAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(CacheManager.class)
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(500)
                .expireAfterWrite(java.time.Duration.ofMinutes(5)));
        return manager;
    }

    @Bean
    @ConditionalOnMissingBean
    public JPAQueryFactory jpaQueryFactory(EntityManager entityManager) {
        return new JPAQueryFactory(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    @ConditionalOnMissingBean
    public ProtectableRapidReentryGuard protectableRapidReentryGuard(
            ProtectableRapidReentryRepository protectableRapidReentryRepository) {
        return new ProtectableRapidReentryGuard(protectableRapidReentryRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationManagerMethodInterceptor protectableAuthorizationAdvisor(
            ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager,
            ProtectableRapidReentryGuard protectableRapidReentryGuard,
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ObjectProvider<SynchronousProtectableDecisionService> synchronousProtectableDecisionServiceProvider) {

        Pointcut pointcut = new ComposablePointcut(classOrMethod());
        AuthorizationManagerMethodInterceptor interceptor = new AuthorizationManagerMethodInterceptor(
                pointcut,
                protectableMethodAuthorizationManager,
                protectableRapidReentryGuard);
        interceptor.setZeroTrustEventPublisher(zeroTrustEventPublisher);
        SynchronousProtectableDecisionService synchronousProtectableDecisionService = synchronousProtectableDecisionServiceProvider.getIfAvailable();
        if (synchronousProtectableDecisionService != null) {
            interceptor.setSynchronousProtectableDecisionService(synchronousProtectableDecisionService);
        }
        return interceptor;
    }

    private static Pointcut classOrMethod() {
        return Pointcuts.union(
                new AnnotationMatchingPointcut(null, Protectable.class, true),
                new AnnotationMatchingPointcut(Protectable.class, true));
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyImpl roleHierarchy() {
        return new RoleHierarchyImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public WebClientCustomizer webClientCustomizer() {

        ConnectionProvider provider = ConnectionProvider.create("custom-ai-pool", 50);

        HttpClient httpClient = HttpClient.create(provider)
                .responseTimeout(Duration.ofMinutes(3));

        return builder -> builder.clientConnector(new ReactorClientHttpConnector(httpClient));
    }
}

