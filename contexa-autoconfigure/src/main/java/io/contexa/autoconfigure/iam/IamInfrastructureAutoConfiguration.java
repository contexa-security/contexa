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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableLlmSuppressionWriter;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import io.contexa.contexaiam.security.xacml.pep.ProtectableResourceCertificationGate;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.beans.factory.annotation.Qualifier;
import io.contexa.contexaiam.security.xacml.pep.DelegatorAuthority;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.cache.CacheManager;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

@Slf4j
@AutoConfiguration
public class IamInfrastructureAutoConfiguration {

    @Bean(name = "contexaJpaQueryFactory")
    @ConditionalOnMissingBean
    public JPAQueryFactory jpaQueryFactory(
            @Qualifier("contexaEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory);
        return new JPAQueryFactory(entityManager);
    }

    /**
     * The encoder of Contexa's own accounts; not the application's PasswordEncoder. Held in a bean of no shared type: Spring Security looks
     * a PasswordEncoder up by type for the application's authentication and finds a sole one even if it is no autowire candidate.
     */
    @Bean(name = "contexaPasswordEncoder")
    @ConditionalOnMissingBean(name = "contexaPasswordEncoder")
    public HeldBean<PasswordEncoder> passwordEncoder() {
        return new HeldBean<>(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    }

    @Bean(name = "contexaWebSecurityCustomizer")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.bridge", name = "ownership", havingValue = "CONTEXA_OWNED")
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean(name = "contexaProtectableRapidReentryGuard")
    @ConditionalOnMissingBean
    public ProtectableRapidReentryGuard protectableRapidReentryGuard(
            ProtectableRapidReentryRepository protectableRapidReentryRepository,
            SecurityZeroTrustProperties zeroTrustProperties) {
        return new ProtectableRapidReentryGuard(
                protectableRapidReentryRepository,
                Duration.ofMillis(Math.max(0L, zeroTrustProperties.getProtectable().getRapidReentryWindowMs())));
    }

    /**
     * The @Protectable method advisor. The auto-proxy creator looks advisors up while post-processors are registered,
     * so this advisor takes its collaborators as providers and resolves them once every singleton exists (or at its
     * first call): resolving them at its creation made their whole graph (the decision service, the language models,
     * the data sources) miss the post-processors not yet registered, and left @Protectable methods among them
     * unprotected. It is an infrastructure bean, as Spring Security's method advisors are.
     */
    @Bean(name = "contexaProtectableAuthorizationAdvisor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean
    public static AuthorizationManagerMethodInterceptor protectableAuthorizationAdvisor(
            ObjectProvider<ProtectableMethodAuthorizationManager> protectableMethodAuthorizationManager,
            ObjectProvider<ProtectableRapidReentryGuard> protectableRapidReentryGuard,
            ObjectProvider<ZeroTrustEventPublisher> zeroTrustEventPublisher,
            ObjectProvider<SynchronousProtectableDecisionService> synchronousProtectableDecisionServiceProvider,
            ObjectProvider<ProtectableResourceCertificationGate> protectableResourceCertificationGateProvider,
            ObjectProvider<ProtectableLlmSuppressionWriter> protectableLlmSuppressionWriterProvider,
            ObjectProvider<AuthorizationDenialRecorder> authorizationDenialRecorderProvider,
            ObjectProvider<SecurityZeroTrustProperties> securityZeroTrustProperties,
            ObjectProvider<DelegatorAuthority> delegatorAuthorityProvider) {

        Pointcut pointcut = new ComposablePointcut(classOrMethod());
        AtomicReference<AuthorizationManagerMethodInterceptor> advisor = new AtomicReference<>();
        AuthorizationManagerMethodInterceptor interceptor = new AuthorizationManagerMethodInterceptor(pointcut, () -> {
            AuthorizationManagerMethodInterceptor resolving = advisor.get();
            resolving.setAuthorizationManager(protectableMethodAuthorizationManager.getObject());
            resolving.setRapidReentryGuard(protectableRapidReentryGuard.getObject());
            resolving.setZeroTrustEventPublisher(zeroTrustEventPublisher.getObject());
            synchronousProtectableDecisionServiceProvider.ifAvailable(resolving::setSynchronousProtectableDecisionService);
            protectableResourceCertificationGateProvider.ifAvailable(resolving::setProtectableResourceCertificationGate);
            protectableLlmSuppressionWriterProvider.ifAvailable(resolving::setProtectableLlmSuppressionWriter);
            authorizationDenialRecorderProvider.ifAvailable(resolving::setAuthorizationDenialRecorder);
            resolving.setSecurityZeroTrustProperties(securityZeroTrustProperties.getObject());
            delegatorAuthorityProvider.ifAvailable(resolving::setDelegatorAuthority);
        });
        advisor.set(interceptor);
        return interceptor;
    }

    @Bean(name = "contexaProtectableLlmSuppressionWriter")
    @ConditionalOnMissingBean
    public ProtectableLlmSuppressionWriter protectableLlmSuppressionWriter(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperationsProvider,
            @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapperProvider,
            @Qualifier("contexaTransactionManager") PlatformTransactionManager transactionManager) {
        ObjectMapper objectMapper = objectMapperProvider.getIfAvailable(ObjectMapper::new);
        return new ProtectableLlmSuppressionWriter(
                jdbcOperationsProvider::getIfAvailable,
                objectMapper,
                transactionManager);
    }

    private static Pointcut classOrMethod() {
        return Pointcuts.union(
                new AnnotationMatchingPointcut(null, Protectable.class, true),
                new AnnotationMatchingPointcut(Protectable.class, true));
    }

    /**
     * Contexa's own role hierarchy, for Contexa's own accounts. Held in a bean of no shared type: Spring Security looks a RoleHierarchy up
     * by type for the application's authorization and finds a sole one even if it is no autowire candidate, and the application's
     * decisions would follow the rules the console of Contexa loads into it.
     */
    @Bean(name = "contexaRoleHierarchy")
    @ConditionalOnMissingBean(name = "contexaRoleHierarchy")
    public HeldBean<RoleHierarchyImpl> roleHierarchy() {
        return new HeldBean<>(new RoleHierarchyImpl());
    }

}


