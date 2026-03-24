package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnProperty(prefix = "contexa.bridge", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(BridgeProperties.class)
public class AiBridgeConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RequestContextCollector requestContextCollector() {
        return new RequestContextCollector();
    }

    @Bean
    @ConditionalOnMissingBean
    public BridgeCoverageEvaluator bridgeCoverageEvaluator() {
        return new BridgeCoverageEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean(AuthBridge.class)
    public AuthBridge authBridge(BridgeProperties properties) {
        return new CompositeAuthBridge(List.of(
                new SessionAuthBridge(properties.getAuthentication().getSession()),
                new RequestAttributeAuthBridge(properties.getAuthentication().getRequestAttributes()),
                new HeaderAuthBridge(properties.getAuthentication().getHeaders())
        ));
    }

    @Bean
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthenticationStampResolver.class)
    public AuthenticationStampResolver securityContextAuthenticationStampResolver() {
        return new SecurityContextAuthenticationStampResolver();
    }

    @Bean
    @Order(10)
    @ConditionalOnMissingBean(AuthBridgeAuthenticationStampResolver.class)
    public AuthenticationStampResolver authBridgeAuthenticationStampResolver(AuthBridge authBridge) {
        return new AuthBridgeAuthenticationStampResolver(authBridge);
    }

    @Bean
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityContextAuthorizationStampResolver() {
        return new SecurityContextAuthorizationStampResolver();
    }

    @Bean
    @Order(5)
    @ConditionalOnMissingBean(SessionAuthorizationStampResolver.class)
    public AuthorizationStampResolver sessionAuthorizationStampResolver() {
        return new SessionAuthorizationStampResolver();
    }

    @Bean
    @Order(10)
    @ConditionalOnMissingBean(RequestAttributeAuthorizationStampResolver.class)
    public AuthorizationStampResolver requestAttributeAuthorizationStampResolver() {
        return new RequestAttributeAuthorizationStampResolver();
    }

    @Bean
    @Order(20)
    @ConditionalOnMissingBean(HeaderAuthorizationStampResolver.class)
    public AuthorizationStampResolver headerAuthorizationStampResolver() {
        return new HeaderAuthorizationStampResolver();
    }

    @Bean
    @Order(5)
    @ConditionalOnMissingBean(SessionDelegationStampResolver.class)
    public DelegationStampResolver sessionDelegationStampResolver() {
        return new SessionDelegationStampResolver();
    }

    @Bean
    @Order(10)
    @ConditionalOnMissingBean(RequestAttributeDelegationStampResolver.class)
    public DelegationStampResolver requestAttributeDelegationStampResolver() {
        return new RequestAttributeDelegationStampResolver();
    }

    @Bean
    @Order(20)
    @ConditionalOnMissingBean(HeaderDelegationStampResolver.class)
    public DelegationStampResolver headerDelegationStampResolver() {
        return new HeaderDelegationStampResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public BridgeResolutionFilter bridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            ObjectProvider<AuthenticationStampResolver> authenticationStampResolvers,
            ObjectProvider<AuthorizationStampResolver> authorizationStampResolvers,
            ObjectProvider<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator) {
        return new BridgeResolutionFilter(
                properties,
                requestContextCollector,
                authenticationStampResolvers.orderedStream().toList(),
                authorizationStampResolvers.orderedStream().toList(),
                delegationStampResolvers.orderedStream().toList(),
                bridgeCoverageEvaluator
        );
    }
}
