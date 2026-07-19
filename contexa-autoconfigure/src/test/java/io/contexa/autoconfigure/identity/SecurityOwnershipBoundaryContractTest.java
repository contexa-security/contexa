/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.autoconfigure.iam.IamInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.iam.IamSecurityAutoConfiguration;
import io.contexa.autoconfigure.iam.IamSecurityCoreAutoConfiguration;
import io.contexa.autoconfigure.iam.IamWebSocketAutoConfiguration;
import io.contexa.autoconfigure.iam.admin.IamAdminIpAutoConfiguration;
import io.contexa.autoconfigure.iam.admin.IamAdminSessionAutoConfiguration;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.config.CoreSecurityAutoConfiguration;
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
        assertContexaOwnedOnly(findMethod(
                IamSecurityCoreAutoConfiguration.class, "customAuthenticationProvider"));
        assertContexaOwnedOnly(findMethod(
                IamSecurityCoreAutoConfiguration.class, "loginAttemptEventListener"));
        assertContexaOwnedOnly(findMethod(
                IamSecurityCoreAutoConfiguration.class, "loginAttemptCleanupFilterRegistration"));
        assertContexaOwnedOnly(findMethod(
                IdentitySecurityCoreAutoConfiguration.class, "securityFilterChain"));
        assertContexaOwnedOnly(findMethod(
                IdentitySecurityCoreAutoConfiguration.class, "webSecurityConfigurationDependencyInjector"));
        assertContexaOwnedOnly(findMethod(
                CoreSecurityAutoConfiguration.class, "unifiedUserDetailsService"));
        assertContexaOwnedOnly(findMethod(
                IamInfrastructureAutoConfiguration.class, "webSecurityCustomizer"));
        assertContexaOwnedOnly(findMethod(
                IamAdminSessionAutoConfiguration.class, "sessionTrackingFilter"));
        assertContexaOwnedOnly(IdentityOAuth2AutoConfiguration.class
                .getAnnotation(ConditionalOnProperty.class));
    }

    @Test
    void hostOwnedModeDoesNotEnableApplicationWideMethodSecurity() {
        assertThat(IamSecurityAutoConfiguration.class.getAnnotation(EnableMethodSecurity.class)).isNull();

        Class<?> ownedConfiguration = Arrays.stream(IamSecurityAutoConfiguration.class.getDeclaredClasses())
                .filter(type -> type.getSimpleName().equals("ContexaOwnedMethodSecurityConfiguration"))
                .findFirst()
                .orElseThrow();

        assertThat(ownedConfiguration.getAnnotation(EnableMethodSecurity.class)).isNotNull();
        assertContexaOwnedOnly(ownedConfiguration.getAnnotation(ConditionalOnProperty.class));
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

    private void assertContexaOwnedOnly(Method method) {
        ConditionalOnProperty condition = Arrays.stream(
                        method.getAnnotationsByType(ConditionalOnProperty.class))
                .filter(candidate -> candidate.prefix().equals("contexa.bridge"))
                .findFirst()
                .orElse(null);
        assertContexaOwnedOnly(condition);
    }

    private void assertContexaOwnedOnly(ConditionalOnProperty condition) {
        assertThat(condition).isNotNull();
        assertThat(condition.prefix()).isEqualTo("contexa.bridge");
        assertThat(condition.name()).containsExactly("ownership");
        assertThat(condition.havingValue()).isEqualTo("CONTEXA_OWNED");
        assertThat(condition.matchIfMissing()).isFalse();
    }
}
