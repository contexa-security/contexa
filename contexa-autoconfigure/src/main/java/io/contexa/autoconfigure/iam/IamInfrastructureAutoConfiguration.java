package io.contexa.autoconfigure.iam;

import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
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
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;


@Slf4j
@AutoConfiguration
public class IamInfrastructureAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public JPAQueryFactory jpaQueryFactory(EntityManager entityManager) {
                return new JPAQueryFactory(entityManager);
    }

    
    @Bean

    @ConditionalOnMissingBean
    public AuthorizationManagerMethodInterceptor protectableAuthorizationAdvisor(
            ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager,
            ZeroTrustEventPublisher zeroTrustEventPublisher) {

        
        Pointcut pointcut = new ComposablePointcut(classOrMethod());
        AuthorizationManagerMethodInterceptor interceptor =
            new AuthorizationManagerMethodInterceptor(pointcut, protectableMethodAuthorizationManager);
        interceptor.setZeroTrustEventPublisher(zeroTrustEventPublisher);
        return interceptor;
    }

    
    private static Pointcut classOrMethod() {
        return Pointcuts.union(
            new AnnotationMatchingPointcut(null, Protectable.class, true),
            new AnnotationMatchingPointcut(Protectable.class, true)
        );
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
