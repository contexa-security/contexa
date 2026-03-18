package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.customizer.*;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Orchestrates post-build customization of SecurityFilterChain filters.
 * Delegates to specialized customizers for each filter type.
 *
 * Responsibilities:
 * 1. Apply per-flow URL prefix to all authentication filter RequestMatchers
 * 2. Replace WebAuthn handlers (success/failure)
 * 3. Replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version
 * 4. Inject per-flow AuthUrlProvider into DefaultMfaPageGeneratingFilter
 */
@Slf4j
public class SecurityFilterChainCustomizer {

    private final PrimaryAuthFilterCustomizer primaryAuthCustomizer = new PrimaryAuthFilterCustomizer();
    private final PasskeyFilterCustomizer passkeyCustomizer = new PasskeyFilterCustomizer();
    private final OttFilterCustomizer ottCustomizer = new OttFilterCustomizer();
    private final MfaPageFilterCustomizer pageCustomizer = new MfaPageFilterCustomizer();
    private final LogoutFilterCustomizer logoutCustomizer = new LogoutFilterCustomizer();

    public void customize(DefaultSecurityFilterChain builtChain,
                          AuthenticationFlowConfig flowConfig,
                          ApplicationContext appContext) {

        boolean isMfaFlow = MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName());
        AuthUrlProvider flowUrlProvider = resolveFlowUrlProvider(flowConfig, appContext);

        AuthenticationStepConfig passkeyStep = findStep(flowConfig, AuthType.PASSKEY, AuthType.MFA_PASSKEY);
        if (passkeyStep != null) {
            passkeyCustomizer.replaceHandlers(builtChain, flowConfig, appContext, isMfaFlow);
            passkeyCustomizer.replaceRegistrationPage(builtChain, appContext);
        }

        if (isMfaFlow && flowUrlProvider != null) {
            primaryAuthCustomizer.customize(builtChain, flowUrlProvider, null);

            if (passkeyStep != null) {
                AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
                PasskeyOptions passkeyOpts = extractPasskeyOptions(passkeyStep);
                passkeyCustomizer.customize(builtChain, flowUrlProvider,
                        new PasskeyFilterCustomizer.PasskeyCustomizerContext(passkeyOpts, authProps));
            }

            if (findStep(flowConfig, AuthType.OTT, AuthType.MFA_OTT) != null) {
                ottCustomizer.customize(builtChain, flowUrlProvider, null);
            }

            pageCustomizer.customize(builtChain, flowUrlProvider, null);
            logoutCustomizer.customize(builtChain, flowUrlProvider, null);
        }
    }

    private AuthenticationStepConfig findStep(AuthenticationFlowConfig flowConfig, AuthType... types) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> {
                    for (AuthType type : types) {
                        if (type.name().equalsIgnoreCase(step.getType())) return true;
                    }
                    return false;
                })
                .findFirst()
                .orElse(null);
    }

    private PasskeyOptions extractPasskeyOptions(AuthenticationStepConfig passkeyStep) {
        Object optionsObj = passkeyStep.getOptions().get("_options");
        return optionsObj instanceof PasskeyOptions opts ? opts : null;
    }

    private AuthUrlProvider resolveFlowUrlProvider(AuthenticationFlowConfig flowConfig, ApplicationContext appContext) {
        try {
            MfaFlowUrlRegistry registry = appContext.getBean(MfaFlowUrlRegistry.class);
            return registry.getProvider(flowConfig.getTypeName());
        } catch (Exception e) {
            return null;
        }
    }
}
