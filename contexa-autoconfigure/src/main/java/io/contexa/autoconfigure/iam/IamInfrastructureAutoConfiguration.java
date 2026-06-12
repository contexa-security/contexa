/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.iam;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import io.contexa.contexaiam.security.xacml.pep.ProtectableResourceCertificationGate;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

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
                .expireAfterWrite(Duration.ofMinutes(5)));
        return manager;
    }

    @Bean
    @ConditionalOnMissingBean
    public JPAQueryFactory jpaQueryFactory(
            @Qualifier("contexaEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory);
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
            ProtectableRapidReentryRepository protectableRapidReentryRepository,
            SecurityZeroTrustProperties zeroTrustProperties) {
        return new ProtectableRapidReentryGuard(
                protectableRapidReentryRepository,
                Duration.ofMillis(Math.max(0L, zeroTrustProperties.getProtectable().getRapidReentryWindowMs())));
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationManagerMethodInterceptor protectableAuthorizationAdvisor(
            ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager,
            ProtectableRapidReentryGuard protectableRapidReentryGuard,
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ObjectProvider<SynchronousProtectableDecisionService> synchronousProtectableDecisionServiceProvider,
            ObjectProvider<ProtectableResourceCertificationGate> protectableResourceCertificationGateProvider,
            SecurityZeroTrustProperties securityZeroTrustProperties) {

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
        ProtectableResourceCertificationGate protectableResourceCertificationGate = protectableResourceCertificationGateProvider.getIfAvailable();
        if (protectableResourceCertificationGate != null) {
            interceptor.setProtectableResourceCertificationGate(protectableResourceCertificationGate);
        }
        interceptor.setSecurityZeroTrustProperties(securityZeroTrustProperties);
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

