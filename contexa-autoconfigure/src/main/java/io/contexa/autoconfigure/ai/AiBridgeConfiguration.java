package io.contexa.autoconfigure.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
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
        BridgeProperties.Session sessionProperties = properties.getAuthentication().getSession();
        BridgeProperties.RequestAttributes requestAttributes = properties.getAuthentication().getRequestAttributes();
        applyAuthObjectHints(sessionProperties, requestAttributes);

        SessionAuthBridge sessionAuthBridge = new SessionAuthBridge(sessionProperties);
        RequestAttributeAuthBridge requestAttributeAuthBridge = new RequestAttributeAuthBridge(requestAttributes);
        HeaderAuthBridge headerAuthBridge = new HeaderAuthBridge(properties.getAuthentication().getHeaders());

        List<AuthBridge> bridges = new ArrayList<>();
        AuthObjectLocation location = resolveAuthObjectLocation();
        if (location == AuthObjectLocation.REQUEST_ATTRIBUTE) {
            bridges.add(requestAttributeAuthBridge);
            bridges.add(sessionAuthBridge);
            bridges.add(headerAuthBridge);
        } else if (location == AuthObjectLocation.HEADER) {
            bridges.add(headerAuthBridge);
            bridges.add(sessionAuthBridge);
            bridges.add(requestAttributeAuthBridge);
        } else {
            bridges.add(sessionAuthBridge);
            bridges.add(requestAttributeAuthBridge);
            bridges.add(headerAuthBridge);
        }
        return new CompositeAuthBridge(bridges);
    }

    @Bean
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthenticationStampResolver.class)
    public AuthenticationStampResolver securityOnAuthenticationStampResolver() {
        return new SecurityContextAuthenticationStampResolver();
    }

    @Bean
    @Order(5)
    @ConditionalOnMissingBean(AuthBridgeAuthenticationStampResolver.class)
    public AuthenticationStampResolver securityOffBridgeAuthenticationStampResolver(AuthBridge authBridge) {
        return new AuthBridgeAuthenticationStampResolver(authBridge);
    }

    @Bean
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOnAuthorizationStampResolver() {
        return new SecurityContextAuthorizationStampResolver();
    }

    @Bean
    @Order(5)
    @ConditionalOnMissingBean(SessionAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOffSessionAuthorizationStampResolver() {
        return new SessionAuthorizationStampResolver();
    }

    @Bean
    @Order(10)
    @ConditionalOnMissingBean(RequestAttributeAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOffRequestAttributeAuthorizationStampResolver() {
        return new RequestAttributeAuthorizationStampResolver();
    }

    @Bean
    @Order(20)
    @ConditionalOnMissingBean(HeaderAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOffHeaderAuthorizationStampResolver() {
        return new HeaderAuthorizationStampResolver();
    }

    @Bean
    @Order(5)
    @ConditionalOnMissingBean(SessionDelegationStampResolver.class)
    public DelegationStampResolver securityOffSessionDelegationStampResolver() {
        return new SessionDelegationStampResolver();
    }

    @Bean
    @Order(10)
    @ConditionalOnMissingBean(RequestAttributeDelegationStampResolver.class)
    public DelegationStampResolver securityOffRequestAttributeDelegationStampResolver() {
        return new RequestAttributeDelegationStampResolver();
    }

    @Bean
    @Order(20)
    @ConditionalOnMissingBean(HeaderDelegationStampResolver.class)
    public DelegationStampResolver securityOffHeaderDelegationStampResolver() {
        return new HeaderDelegationStampResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({UserRepository.class, BridgeUserProfileRepository.class})
    public BridgeUserMirrorSyncService bridgeUserMirrorSyncService(
            UserRepository userRepository,
            BridgeUserProfileRepository bridgeUserProfileRepository,
            BridgeProperties properties,
            ObjectProvider<ObjectMapper> objectMapperProvider,
            ObjectProvider<CacheManager> cacheManagerProvider) {
        return new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                objectMapperProvider.getIfAvailable(ObjectMapper::new),
                cacheManagerProvider.getIfAvailable()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public BridgeResolutionFilter bridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector requestContextCollector,
            ObjectProvider<AuthenticationStampResolver> authenticationStampResolvers,
            ObjectProvider<AuthorizationStampResolver> authorizationStampResolvers,
            ObjectProvider<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator bridgeCoverageEvaluator,
            ObjectProvider<BridgeUserMirrorSyncService> bridgeUserMirrorSyncService) {
        return new BridgeResolutionFilter(
                properties,
                requestContextCollector,
                authenticationStampResolvers.orderedStream().toList(),
                authorizationStampResolvers.orderedStream().toList(),
                delegationStampResolvers.orderedStream().toList(),
                bridgeCoverageEvaluator,
                bridgeUserMirrorSyncService.getIfAvailable()
        );
    }

    private void applyAuthObjectHints(
            BridgeProperties.Session sessionProperties,
            BridgeProperties.RequestAttributes requestAttributes) {
        String authObjectType = resolveAuthObjectType();
        if (authObjectType != null) {
            sessionProperties.setObjectTypeName(authObjectType);
            requestAttributes.setObjectTypeName(authObjectType);
        }

        String authObjectAttribute = resolveAuthObjectAttribute();
        if (authObjectAttribute == null) {
            return;
        }

        AuthObjectLocation location = resolveAuthObjectLocation();
        if (location == AuthObjectLocation.SESSION) {
            sessionProperties.setAttribute(authObjectAttribute);
        } else if (location == AuthObjectLocation.REQUEST_ATTRIBUTE) {
            requestAttributes.setAttribute(authObjectAttribute);
        }
    }

    private AuthObjectLocation resolveAuthObjectLocation() {
        String configured = System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION);
        if (configured == null || configured.isBlank()) {
            return AuthObjectLocation.AUTO;
        }
        try {
            return AuthObjectLocation.valueOf(configured.trim().toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return AuthObjectLocation.AUTO;
        }
    }

    private String resolveAuthObjectAttribute() {
        String configured = System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE);
        if (configured == null) {
            return null;
        }
        String normalized = configured.trim();
        return normalized.isBlank() ? null : normalized;
    }

    private String resolveAuthObjectType() {
        String configured = System.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_TYPE);
        if (configured == null) {
            return null;
        }
        String normalized = configured.trim();
        if (normalized.isBlank() || Object.class.getName().equals(normalized)) {
            return null;
        }
        return normalized;
    }
}
