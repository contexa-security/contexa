/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.config.CoreSecurityContexaOwnedConfiguration;
import io.contexa.autoconfigure.iam.admin.IamAdminSessionContexaOwnedConfiguration;
import io.contexa.autoconfigure.iam.IamInfrastructureContexaOwnedConfiguration;
import io.contexa.autoconfigure.iam.IamSecurityCoreContexaOwnedConfiguration;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.autoconfigure.iam.IamSecurityAutoConfiguration;
import io.contexa.autoconfigure.iam.IamWebSocketAutoConfiguration;
import io.contexa.autoconfigure.iam.admin.IamAdminIpAutoConfiguration;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityOwnershipBoundaryContractTest {

    @Test
    void hostOwnedModeCannotMaterializeContexaAuthenticationInfrastructure() {
        assertInContexaOwnedPlane(IamSecurityCoreContexaOwnedConfiguration.class, "customAuthenticationProvider");
        assertInContexaOwnedPlane(IamSecurityCoreContexaOwnedConfiguration.class, "loginAttemptEventListener");
        assertInContexaOwnedPlane(IamSecurityCoreContexaOwnedConfiguration.class, "loginAttemptCleanupFilterRegistration");
        assertInContexaOwnedPlane(IdentitySecurityCoreContexaOwnedConfiguration.class, "securityFilterChain");
        assertInContexaOwnedPlane(IdentitySecurityCoreContexaOwnedConfiguration.class, "webSecurityConfigurationDependencyInjector");
        assertInContexaOwnedPlane(CoreSecurityContexaOwnedConfiguration.class, "unifiedUserDetailsService");
        assertInContexaOwnedPlane(IamInfrastructureContexaOwnedConfiguration.class, "webSecurityCustomizer");
        assertInContexaOwnedPlane(IamAdminSessionContexaOwnedConfiguration.class, "sessionTrackingFilter");
        assertContexaOwnedOnly(IdentityOAuth2AutoConfiguration.class
                .getAnnotation(ConditionalOnOwnership.class));
    }

    @Test
    void hostOwnedModeDoesNotEnableApplicationWideMethodSecurity() {
        assertThat(IamSecurityAutoConfiguration.class.getAnnotation(EnableMethodSecurity.class)).isNull();

        Class<?> ownedConfiguration = Arrays.stream(IamSecurityAutoConfiguration.class.getDeclaredClasses())
                .filter(type -> type.getSimpleName().equals("ContexaOwnedMethodSecurityConfiguration"))
                .findFirst()
                .orElseThrow();

        assertThat(ownedConfiguration.getAnnotation(EnableMethodSecurity.class))
                .as("not even Contexa-owned mode switches method security on for the whole application: the application's"
                        + " dormant @PreAuthorize annotations stay dormant")
                .isNull();
        assertThat(findMethod(ownedConfiguration, "contexaPreAuthorizeAdvisor"))
                .as("Contexa's @PreAuthorize is served by an advisor narrowed to Contexa's classes")
                .isNotNull();
        assertContexaOwnedOnly(ownedConfiguration.getAnnotation(ConditionalOnOwnership.class));
    }

    @Test
    void ipFilterIsLimitedToContexaRoutesWhenHostOwnsSecurity() {
        IamAdminIpAutoConfiguration configuration = new IamAdminIpAutoConfiguration();
        IpAccessRuleService service = mock(IpAccessRuleService.class);
        TieredStrategyProperties tieredProperties = new TieredStrategyProperties();
        BridgeProperties bridgeProperties = new BridgeProperties();

        assertThat(configuration.ipAccessFilter(service, tieredProperties, bridgeProperties).getUrlPatterns())
                .containsExactly("/contexa/*");

        bridgeProperties.setOwnership(SecurityOwnershipMode.CONTEXA_OWNED);

        assertThat(configuration.ipAccessFilter(service, tieredProperties, bridgeProperties).getUrlPatterns())
                .containsExactly("/*");
    }

    @Test
    void dependencyOnlyDoesNotActivateIamWebSocketAndSandboxCanDisableIt() {
        ConditionalOnBean activation = IamWebSocketAutoConfiguration.class
                .getAnnotation(ConditionalOnBean.class);
        assertThat(activation).isNotNull();
        assertThat(activation.value()).containsExactly(PlatformConfig.class);

        ConditionalOnProperty enabled = IamWebSocketAutoConfiguration.class
                .getAnnotation(ConditionalOnProperty.class);
        assertThat(enabled).isNotNull();
        assertThat(enabled.prefix()).isEqualTo("contexa.iam.websocket");
        assertThat(enabled.name()).containsExactly("enabled");
        assertThat(enabled.havingValue()).isEqualTo("true");
        assertThat(enabled.matchIfMissing()).isTrue();
    }

    private Method findMethod(Class<?> type, String name) {
        return Arrays.stream(type.getDeclaredMethods())
                .filter(method -> method.getName().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private void assertInContexaOwnedPlane(Class<?> plane, String method) {
        assertThat(findMethod(plane, method)).isNotNull();
        assertContexaOwnedOnly(plane.getAnnotation(ConditionalOnOwnership.class));
    }

    private void assertContexaOwnedOnly(ConditionalOnOwnership condition) {
        assertThat(condition).isNotNull();
        assertThat(condition.value()).isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED);
        assertThat(condition.matchIfUndeclared()).isFalse();
    }
}
