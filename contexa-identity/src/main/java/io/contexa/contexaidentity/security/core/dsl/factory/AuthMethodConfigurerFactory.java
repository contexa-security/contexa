package io.contexa.contexaidentity.security.core.dsl.factory;

import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.*;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

import java.util.Objects;

@Slf4j
public final class AuthMethodConfigurerFactory {

    private final ApplicationContext applicationContext;

    public AuthMethodConfigurerFactory(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
    }

    public <O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            S extends AuthenticationFactorConfigurer<O, A, S>>
    S createFactorConfigurer(AuthType authType, Class<S> configurerInterfaceType) { // HttpSecurityBuilder 인자 제거
        Objects.requireNonNull(authType, "AuthType cannot be null");
        Objects.requireNonNull(configurerInterfaceType, "ConfigurerInterfaceType cannot be null");

        // 각 Configurer는 ApplicationContext를 필요로 할 수 있음 (예: 빈 이름으로 핸들러 참조)
        Object concreteConfigurerLogic = switch (authType) {
            case FORM -> {
                yield new FormDslConfigurerImpl(this.applicationContext);
            }
            case MFA_FORM -> {
                yield new FormDslConfigurerImpl(this.applicationContext, true);
            }
            case REST -> {
                yield new RestDslConfigurerImpl(this.applicationContext);
            }
            case MFA_REST -> {
                yield new RestDslConfigurerImpl(this.applicationContext, true);
            }

            case OTT -> {
                yield new OttDslConfigurerImpl(this.applicationContext);
            }
            case MFA_OTT -> {
                yield new OttDslConfigurerImpl(this.applicationContext, true);
            }
            case PASSKEY -> {
                yield new PasskeyDslConfigurerImpl(this.applicationContext);
            }
            case MFA_PASSKEY -> {
                yield new PasskeyDslConfigurerImpl(this.applicationContext, true);
            }
            // case RECOVERY_CODE -> { ... }
            default -> {
                log.error("AuthMethodConfigurerFactory: Unsupported AuthType for AuthenticationFactorConfigurer: {}", authType);
                throw new IllegalArgumentException("Unsupported AuthType for AuthenticationFactorConfigurer: " + authType);
            }
        };

        if (configurerInterfaceType.isInstance(concreteConfigurerLogic)) {
            return configurerInterfaceType.cast(concreteConfigurerLogic);
        } else {
            log.error("AuthMethodConfigurerFactory: Created configurer of type {} is not assignable to expected interface {}.",
                    concreteConfigurerLogic.getClass().getName(), configurerInterfaceType.getSimpleName());
            throw new IllegalArgumentException("Created configurer type mismatch. Expected: " +
                    configurerInterfaceType.getSimpleName() + ", Actual: " + concreteConfigurerLogic.getClass().getName());
        }
    }

    public <H extends HttpSecurityBuilder<H>> PrimaryAuthDslConfigurerImpl<H> createPrimaryAuthConfigurer(ApplicationContext context) {
        return new PrimaryAuthDslConfigurerImpl<>(context); // HttpSecurityBuilder 인자 제거
    }

    public <H extends HttpSecurityBuilder<H>> MfaDslConfigurerImpl<H> createMfaConfigurer(ApplicationContext context) {
        return new MfaDslConfigurerImpl<>(context); // HttpSecurityBuilder 인자 제거
    }
}