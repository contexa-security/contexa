/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.config.CoreSecurityUserStoreConfiguration;
import io.contexa.autoconfigure.iam.IamPasswordSignInConfiguration;
import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.junit.jupiter.api.DisplayName;
import io.contexa.autoconfigure.iam.admin.IamAdminSessionTrackingConfiguration;
import io.contexa.autoconfigure.iam.IamFullModeInfrastructureConfiguration;
import io.contexa.autoconfigure.iam.IamSignInAttemptConfiguration;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.autoconfigure.iam.IamSecurityAutoConfiguration;
import io.contexa.autoconfigure.iam.IamWebSocketAutoConfiguration;
import io.contexa.autoconfigure.iam.admin.IamAdminIpAutoConfiguration;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaidentity.security.zerotrust.SandboxSignInFailureListener;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.properties.IamAdminProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityOwnershipBoundaryContractTest {

    /**
     * R-13 and R-17 of docs/agent/운영모드-정상화-구현계획.md: Contexa's administrators sign in with MFA in every way of running
     * Contexa, so its user store, its password provider and its sign-in handlers exist in all four. They are offered by type
     * only where Contexa's main chain signs the application's users in (FULL) and the application has none of its own;
     * elsewhere they are held. The placeholder chain belongs to the main chain (FULL).
     */
    @Test
    @DisplayName("Contexa 로그인 장치는 네 조합 모두에 있고 타입 빈은 FULL에서만 내놓는다(R-13, R-17)")
    void contexasSignInExistsInEveryWayOfRunningAndIsOfferedByTypeOnlyInFull() {
        assertThat(CoreSecurityUserStoreConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertOfferedInFullOnly(CoreSecurityUserStoreConfiguration.class, "unifiedUserDetailsService", "heldUnifiedUserDetailsService");
        assertThat(IamPasswordSignInConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertOfferedInFullOnly(IamPasswordSignInConfiguration.class, "customAuthenticationProvider", "heldCustomAuthenticationProvider");
        assertThat(IdentitySignInConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertThat(findMethod(IdentitySignInConfiguration.class, "securityFilterChain").getAnnotation(ConditionalOnMode.class).value())
                .isEqualTo(SecurityMode.FULL);
        assertThat(findMethod(IdentitySignInConfiguration.class, "webSecurityConfigurationDependencyInjector")
                .getAnnotation(ConditionalOnMode.class)).as("the flow chains of every way of running reach Spring's proxy").isNull();
    }

    /**
     * M4 of docs/agent/운영모드-정상화-구현계획.md: the sign-in attempt policy and the session tracking are there in every way of
     * running Contexa. The mode decides the rest: the static resources stay outside the chain where Contexa is the main
     * security configuration (FULL), a setting of the whole application's security, and the step-up of the application's
     * users is there where the application signs them in itself (SANDBOX, R-16).
     */
    @Test
    @DisplayName("로그인 시도 정책과 세션 추적은 네 조합 모두에 있고, 정적 자원 제외는 FULL에, step-up은 SANDBOX에 있다(M4)")
    void signInAttemptsAndSessionTrackingAreThereInEveryWayOfRunningAndTheModeDecidesTheRest() {
        assertThat(IamSignInAttemptConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertThat(IamSignInAttemptConfiguration.class.getAnnotation(ConditionalOnMode.class)).isNull();
        assertThat(findMethod(IamSignInAttemptConfiguration.class, "loginAttemptEventListener")).isNotNull();
        assertThat(findMethod(IamSignInAttemptConfiguration.class, "loginAttemptCleanupFilterRegistration")).isNotNull();
        assertThat(IamAdminSessionTrackingConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertThat(IamAdminSessionTrackingConfiguration.class.getAnnotation(ConditionalOnMode.class)).isNull();
        assertThat(findMethod(IamAdminSessionTrackingConfiguration.class, "sessionTrackingFilter")).isNotNull();
        assertThat(IamFullModeInfrastructureConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertThat(IamFullModeInfrastructureConfiguration.class.getAnnotation(ConditionalOnMode.class).value())
                .isEqualTo(SecurityMode.FULL);
        assertThat(SandboxStepUpAutoConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertThat(SandboxStepUpAutoConfiguration.class.getAnnotation(ConditionalOnMode.class).value())
                .isEqualTo(SecurityMode.SANDBOX);
    }

    /**
     * Contexa's OAuth2 plane is there where Contexa is the main security configuration (mode FULL), whatever the ownership
     * (R-11 of docs/agent/운영모드-정상화-구현계획.md). Its components of the types Spring Boot and Spring Security pick by type for
     * the application are offered by type only where the application has none (R-17); elsewhere they are held under the
     * same names.
     */
    @Test
    @DisplayName("OAuth2 평면은 FULL에만 있고 앱이 타입으로 찾는 구성요소는 앱에 없을 때만 타입 빈이다(R-11, R-17)")
    void theOAuth2PlaneIsThereInFullAndOffersItsSharedTypesOnlyWhereTheApplicationHasNone() {
        assertThat(IdentityOAuth2AutoConfiguration.class.getAnnotation(ConditionalOnOwnership.class)).isNull();
        assertThat(IdentityOAuth2AutoConfiguration.class.getAnnotation(ConditionalOnMode.class).value())
                .isEqualTo(SecurityMode.FULL);
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "offeredJwtDecoder", "heldJwtDecoder");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "offeredJwtEncoder", "heldJwtEncoder");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "jwkSource", "heldJwkSource");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "offeredAuthorizationService", "heldAuthorizationService");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "registeredClientRepository", "heldRegisteredClientRepository");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "authorizationServerSettings", "heldAuthorizationServerSettings");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "offeredClientRegistrationRepository",
                "heldClientRegistrationRepository");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "authorizedClientRepository", "heldAuthorizedClientRepository");
        assertOfferedInFullOnly(IdentityOAuth2AutoConfiguration.class, "offeredAuthorizedClientManager", "heldAuthorizedClientManager");
    }

    /**
     * The step-up's listener of the application's failed sign-ins hands them to the decisions only; the login policy hears
     * them through its own listener, which counts them against the address and touches no account of Contexa's.
     */
    @Test
    @DisplayName("앱 로그인 실패를 판정으로 보내는 리스너는 로그인 정책을 부르지 않는다")
    void theStepUpsListenerOfFailedSignInsDoesNotCallTheLoginPolicy() {
        Method bean = findMethod(SandboxStepUpAutoConfiguration.class, "sandboxSignInFailureListener");

        assertThat(bean).isNotNull();
        assertThat(bean.getParameterTypes()).doesNotContain(LoginPolicyHandler.class);
        assertThat(Arrays.stream(SandboxSignInFailureListener.class.getDeclaredFields()).map(Field::getType).toList())
                .doesNotContain(LoginPolicyHandler.class);
    }

    @Test
    void hostOwnedModeDoesNotEnableApplicationWideMethodSecurity() {
        assertThat(IamSecurityAutoConfiguration.class.getAnnotation(EnableMethodSecurity.class)).isNull();

        Class<?> ownedConfiguration = Arrays.stream(IamSecurityAutoConfiguration.class.getDeclaredClasses())
                .filter(type -> type.getSimpleName().equals("ContexaScopedMethodSecurityConfiguration"))
                .findFirst()
                .orElseThrow();

        assertThat(ownedConfiguration.getAnnotation(EnableMethodSecurity.class))
                .as("not even Contexa-owned mode switches method security on for the whole application: the application's"
                        + " dormant @PreAuthorize annotations stay dormant")
                .isNull();
        assertThat(findMethod(ownedConfiguration, "contexaPreAuthorizeAdvisor"))
                .as("Contexa's @PreAuthorize is served by an advisor narrowed to Contexa's classes")
                .isNotNull();
        assertThat(ownedConfiguration.getAnnotation(ConditionalOnOwnership.class))
                .as("M4 of docs/agent/운영모드-정상화-구현계획.md: Contexa's classes are guarded in every way of running Contexa")
                .isNull();
    }

    /**
     * M4 of docs/agent/운영모드-정상화-구현계획.md (R-12): the address control is no switch of the ownership or the mode. It
     * covers the paths its setting names, every path unless the operator narrows them, in every way of running Contexa.
     */
    @Test
    @DisplayName("주소 통제는 운영 방식이 아니라 설정이 정한 경로(기본 모든 경로)에 걸린다")
    void theAddressControlCoversThePathsItsSettingNamesInEveryWayOfRunning() {
        Method bean = findMethod(IamAdminIpAutoConfiguration.class, "ipAccessFilter");

        assertThat(bean.getParameterTypes()).doesNotContain(BridgeProperties.class);
        assertThat(new IamAdminIpAutoConfiguration().ipAccessFilter(mock(IpAccessRuleService.class), new TieredStrategyProperties(),
                        new IamAdminProperties(), new DefaultListableBeanFactory().getBeanProvider(SecurityProperties.class))
                .getUrlPatterns())
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

    private void assertOfferedInFullOnly(Class<?> configuration, String offered, String held) {
        assertThat(findMethod(configuration, offered).getAnnotation(ConditionalOnMode.class).value()).isEqualTo(SecurityMode.FULL);
        assertThat(findMethod(configuration, held).getReturnType()).isEqualTo(HeldBean.class);
        assertThat(findMethod(configuration, held).getAnnotation(ConditionalOnMode.class)).isNull();
    }
}
