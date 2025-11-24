package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.bootstrap.*;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.validator.DslValidator;
import io.contexa.contexaidentity.security.core.validator.DslValidatorService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.util.List;

/**
 * Identity Security Core AutoConfiguration
 *
 * <p>
 * Contexa Identity의 Security Core 관련 자동 구성을 제공합니다.
 * Bootstrap, DSL, Validator 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>포함된 Configuration:</h3>
 * <ul>
 *   <li>SecurityPlatformConfiguration - 플랫폼 보안 설정</li>
 *   <li>MfaInfrastructureAutoConfiguration - MFA 인프라 구성</li>
 * </ul>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>DSL: IdentityDslRegistry</li>
 *   <li>Validator: DslValidatorService</li>
 *   <li>Bootstrap: WebSecurityConfigurationDependencyInjector, DefaultSecurityConfigurerProvider</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     security-core:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.identity.security-core",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@Import({
    SecurityPlatformConfiguration.class,
    MfaInfrastructureAutoConfiguration.class
})
public class IdentitySecurityCoreAutoConfiguration {

    public IdentitySecurityCoreAutoConfiguration() {
        // Security Core 관련 빈 등록
    }

    // ========== Level 1: DSL (1개) ==========

    /**
     * 1-1. IdentityDslRegistry - Identity DSL 레지스트리
     */
    @Bean
    @ConditionalOnMissingBean
    public IdentityDslRegistry identityDslRegistry(ApplicationContext applicationContext) {
        return new IdentityDslRegistry(applicationContext);
    }

    // ========== Level 2: Validator (1개) ==========

    /**
     * 2-1. DslValidatorService - DSL 검증 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public DslValidatorService dslValidatorService(DslValidator dslValidator) {
        return new DslValidatorService(dslValidator);
    }

    // ========== Level 3: Bootstrap (2개) ==========

    /**
     * 3-1. WebSecurityConfigurationDependencyInjector - WebSecurityConfiguration 의존성 주입기
     */
    @Bean
    @ConditionalOnMissingBean
    public WebSecurityConfigurationDependencyInjector webSecurityConfigurationDependencyInjector() {
        return new WebSecurityConfigurationDependencyInjector();
    }

    /**
     * 3-2. DefaultSecurityConfigurerProvider - 기본 SecurityConfigurer 제공자
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultSecurityConfigurerProvider defaultSecurityConfigurerProvider(
            List<SecurityConfigurer> baseConfigurers,
            AdapterRegistry adapterRegistry,
            ApplicationContext applicationContext) {
        return new DefaultSecurityConfigurerProvider(baseConfigurers, adapterRegistry, applicationContext);
    }
}
