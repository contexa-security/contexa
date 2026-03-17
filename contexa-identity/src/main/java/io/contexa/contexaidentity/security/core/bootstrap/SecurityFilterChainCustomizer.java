package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.filter.ContexaWebAuthnRegistrationPageFilter;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.util.StringUtils;

/**
 * Customizes WebAuthn filters in each SecurityFilterChain.
 * Extracted from SecurityFilterChainRegistrar for single responsibility.
 *
 * Responsibilities:
 * 1. Replace WebAuthnAuthenticationFilter handlers (success/failure)
 * 2. Apply custom URLs from PasskeyOptions to Spring Security WebAuthn filters
 * 3. Replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version
 */
@Slf4j
public class SecurityFilterChainCustomizer {

    public void customize(DefaultSecurityFilterChain builtChain,
                          AuthenticationFlowConfig flowConfig,
                          ApplicationContext appContext) {

        boolean isMfaFlow = MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName());

        AuthenticationStepConfig passkeyStep = findPasskeyStep(flowConfig);
        if (passkeyStep != null) {
            PasskeyOptions passkeyOpts = extractPasskeyOptions(passkeyStep);
            replaceHandlers(builtChain, flowConfig, appContext, isMfaFlow);
            if (isMfaFlow) {
                applyCustomPasskeyUrls(builtChain, flowConfig, appContext, passkeyOpts);
            }
            replaceRegistrationPage(builtChain, appContext);
        }

        AuthenticationStepConfig ottStep = findOttStep(flowConfig);
        if (ottStep != null && isMfaFlow && flowConfig.getUrlPrefix() != null) {
            applyCustomOttUrls(builtChain, flowConfig, appContext);
        }
    }

    private AuthenticationStepConfig findPasskeyStep(AuthenticationFlowConfig flowConfig) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> AuthType.PASSKEY.name().equalsIgnoreCase(step.getType()) ||
                        AuthType.MFA_PASSKEY.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .orElse(null);
    }

    private AuthenticationStepConfig findOttStep(AuthenticationFlowConfig flowConfig) {
        return flowConfig.getStepConfigs().stream()
                .filter(step -> AuthType.OTT.name().equalsIgnoreCase(step.getType()) ||
                        AuthType.MFA_OTT.name().equalsIgnoreCase(step.getType()))
                .findFirst()
                .orElse(null);
    }

    private PasskeyOptions extractPasskeyOptions(AuthenticationStepConfig passkeyStep) {
        Object optionsObj = passkeyStep.getOptions().get("_options");
        if (optionsObj instanceof PasskeyOptions opts) {
            return opts;
        }
        return null;
    }

    private void replaceHandlers(DefaultSecurityFilterChain builtChain,
                                  AuthenticationFlowConfig flowConfig,
                                  ApplicationContext appContext,
                                  boolean isMfaFlow) {

        for (Filter filter : builtChain.getFilters()) {
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter) {
                String filterClassName = filter.getClass().getSimpleName();

                if (filterClassName.contains("WebAuthn")) {
                    try {
                        AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
                        StateType stateType = (flowConfig.getStateConfig() != null && flowConfig.getStateConfig().stateType() != null) ?
                                flowConfig.getStateConfig().stateType() : authProps.getStateType();

                        PlatformAuthenticationSuccessHandler customSuccessHandler;
                        PlatformAuthenticationFailureHandler customFailureHandler;

                        if (isMfaFlow) {
                            customSuccessHandler = appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                            customFailureHandler = appContext.getBean(UnifiedAuthenticationFailureHandler.class);
                        } else {
                            if (stateType == StateType.SESSION) {
                                customSuccessHandler = null;
                                customFailureHandler = null;
                            } else {
                                customSuccessHandler = appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
                                customFailureHandler = appContext.getBean(OAuth2SingleAuthFailureHandler.class);
                            }
                        }

                        if (customSuccessHandler != null) {
                            authFilter.setAuthenticationSuccessHandler(customSuccessHandler);
                        }
                        if (customFailureHandler != null) {
                            authFilter.setAuthenticationFailureHandler(customFailureHandler);
                        }

                        return;

                    } catch (Exception e) {
                        log.error("Failed to replace WebAuthn handlers for flow: {}", flowConfig.getTypeName(), e);
                    }
                }
            }
        }

        log.error("WebAuthnAuthenticationFilter not found in filter chain for flow: {}. " +
                        "Passkey authentication may not work properly without custom handlers.",
                flowConfig.getTypeName());
    }

    private void applyCustomPasskeyUrls(DefaultSecurityFilterChain builtChain,
                                  AuthenticationFlowConfig flowConfig,
                                  ApplicationContext appContext,
                                  PasskeyOptions passkeyOpts) {

        if (flowConfig.getUrlPrefix() == null) {
            return;
        }

        // Use per-flow AuthUrlProvider (with urlPrefix applied) when available
        AuthUrlProvider flowUrlProvider = resolveFlowUrlProvider(flowConfig, appContext);
        AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);

        // Resolve loginProcessingUrl: per-flow AuthUrlProvider > PasskeyOptions (DSL) > properties
        String loginProcessingUrl;
        if (flowUrlProvider != null) {
            loginProcessingUrl = flowUrlProvider.getPasskeyLoginProcessing();
        } else if (passkeyOpts != null && StringUtils.hasText(passkeyOpts.getLoginProcessingUrl())) {
            loginProcessingUrl = passkeyOpts.getLoginProcessingUrl();
        } else {
            loginProcessingUrl = authProps.getUrls().getFactors().getPasskey().getLoginProcessing();
        }

        // Resolve assertionOptionsEndpoint: per-flow AuthUrlProvider > PasskeyOptions (DSL) > properties
        String assertionOptionsUrl;
        if (flowUrlProvider != null) {
            assertionOptionsUrl = flowUrlProvider.getPasskeyAssertionOptions();
        } else if (passkeyOpts != null && StringUtils.hasText(passkeyOpts.getAssertionOptionsEndpoint())) {
            assertionOptionsUrl = passkeyOpts.getAssertionOptionsEndpoint();
        } else {
            assertionOptionsUrl = authProps.getUrls().getFactors().getPasskey().getAssertionOptions();
        }

        for (Filter filter : builtChain.getFilters()) {
            String filterClassName = filter.getClass().getSimpleName();

            // WebAuthnAuthenticationFilter - loginProcessingUrl
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter
                    && filterClassName.contains("WebAuthn") && !filterClassName.contains("Registration")) {
                if (StringUtils.hasText(loginProcessingUrl)) {
                    RequestMatcher customMatcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.POST, loginProcessingUrl);
                    authFilter.setRequiresAuthenticationRequestMatcher(customMatcher);
                }
            }

            // PublicKeyCredentialRequestOptionsFilter - assertionOptionsEndpoint
            if (filter instanceof PublicKeyCredentialRequestOptionsFilter requestOptionsFilter) {
                if (StringUtils.hasText(assertionOptionsUrl)) {
                    RequestMatcher customMatcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.POST, assertionOptionsUrl);
                    requestOptionsFilter.setRequestMatcher(customMatcher);
                }
            }

            // PublicKeyCredentialCreationOptionsFilter - registrationOptionsEndpoint
            if (filter instanceof PublicKeyCredentialCreationOptionsFilter creationOptionsFilter) {
                String registrationOptionsUrl = flowUrlProvider != null
                        ? flowUrlProvider.getPasskeyRegistrationOptions()
                        : resolveRegistrationOptionsUrl(passkeyOpts, authProps);
                if (StringUtils.hasText(registrationOptionsUrl)) {
                    RequestMatcher customMatcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.POST, registrationOptionsUrl);
                    creationOptionsFilter.setRequestMatcher(customMatcher);
                }
            }

            // WebAuthnRegistrationFilter - registerEndpoint
            if (filter instanceof WebAuthnRegistrationFilter registrationFilter) {
                String registerUrl = flowUrlProvider != null
                        ? flowUrlProvider.getPasskeyRegistrationProcessing()
                        : resolveRegisterUrl(passkeyOpts, authProps);
                if (StringUtils.hasText(registerUrl)) {
                    RequestMatcher registerMatcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.POST, registerUrl);
                    registrationFilter.setRegisterCredentialMatcher(registerMatcher);
                }
            }
        }
    }

    private void applyCustomOttUrls(DefaultSecurityFilterChain builtChain,
                                     AuthenticationFlowConfig flowConfig,
                                     ApplicationContext appContext) {

        AuthUrlProvider flowUrlProvider = resolveFlowUrlProvider(flowConfig, appContext);
        if (flowUrlProvider == null) {
            return;
        }

        String ottLoginProcessingUrl = flowUrlProvider.getOttLoginProcessing();
        String ottTokenGeneratingUrl = flowUrlProvider.getOttCodeGeneration();

        for (Filter filter : builtChain.getFilters()) {
            String filterClassName = filter.getClass().getSimpleName();

            // OneTimeTokenAuthenticationFilter - loginProcessingUrl
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter
                    && filterClassName.contains("OneTimeToken") && filterClassName.contains("Authentication")) {
                if (StringUtils.hasText(ottLoginProcessingUrl)) {
                    RequestMatcher customMatcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.POST, ottLoginProcessingUrl);
                    authFilter.setRequiresAuthenticationRequestMatcher(customMatcher);
                }
            }

            // GenerateOneTimeTokenFilter - tokenGeneratingUrl
            if (filter instanceof GenerateOneTimeTokenFilter generateOttFilter) {
                if (StringUtils.hasText(ottTokenGeneratingUrl)) {
                    RequestMatcher customMatcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.POST, ottTokenGeneratingUrl);
                    generateOttFilter.setRequestMatcher(customMatcher);
                }
            }
        }
    }

    private void replaceRegistrationPage(DefaultSecurityFilterChain builtChain, ApplicationContext appContext) {
        try {
            PublicKeyCredentialUserEntityRepository userEntities =
                    appContext.getBean(PublicKeyCredentialUserEntityRepository.class);
            UserCredentialRepository userCredentials =
                    appContext.getBean(UserCredentialRepository.class);

            ContexaWebAuthnRegistrationPageFilter contexaFilter =
                    new ContexaWebAuthnRegistrationPageFilter(userEntities, userCredentials);

            // Find and replace Spring Security's DefaultWebAuthnRegistrationPageGeneratingFilter
            java.util.List<Filter> filters = builtChain.getFilters();
            for (int i = 0; i < filters.size(); i++) {
                String filterClassName = filters.get(i).getClass().getSimpleName();
                if (filterClassName.equals("DefaultWebAuthnRegistrationPageGeneratingFilter")) {
                    filters.set(i, contexaFilter);
                    return;
                }
            }
        } catch (Exception e) {
            log.error("Failed to replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version", e);
        }
    }

    private AuthUrlProvider resolveFlowUrlProvider(AuthenticationFlowConfig flowConfig, ApplicationContext appContext) {
        try {
            MfaFlowUrlRegistry registry = appContext.getBean(MfaFlowUrlRegistry.class);
            return registry.getProvider(flowConfig.getTypeName());
        } catch (Exception e) {
            return null;
        }
    }

    private String resolveRegistrationOptionsUrl(PasskeyOptions passkeyOpts, AuthContextProperties authProps) {
        return authProps.getUrls().getFactors().getPasskey().getRegistrationOptions();
    }

    private String resolveRegisterUrl(PasskeyOptions passkeyOpts, AuthContextProperties authProps) {
        return authProps.getUrls().getFactors().getPasskey().getRegistrationProcessing();
    }
}
