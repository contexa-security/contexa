package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.filter.ContexaWebAuthnRegistrationPageFilter;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Applies per-flow URL prefix to WebAuthn (Passkey) filters.
 * Also handles WebAuthn handler replacement and registration page replacement.
 *
 * Targets: WebAuthnAuthenticationFilter, PublicKeyCredentialRequestOptionsFilter,
 *          PublicKeyCredentialCreationOptionsFilter, WebAuthnRegistrationFilter
 */
@Slf4j
public class PasskeyFilterCustomizer extends AbstractFilterCustomizer {

    /**
     * Apply per-flow URLs to all WebAuthn filters.
     *
     * @param context PasskeyCustomizerContext containing passkeyOpts and authProps
     */
    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        PasskeyCustomizerContext ctx = (PasskeyCustomizerContext) context;

        for (Filter filter : getFilters(builtChain)) {

            // WebAuthnAuthenticationFilter - loginProcessingUrl
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter && isWebAuthnAuth(filter)) {
                setMatcherIfPresent(authFilter, resolveLoginProcessing(flowUrlProvider, ctx.passkeyOpts(), ctx.authProps()));
            }

            // PublicKeyCredentialRequestOptionsFilter - assertionOptionsEndpoint
            if (filter instanceof PublicKeyCredentialRequestOptionsFilter optionsFilter) {
                String url = resolveAssertionOptions(flowUrlProvider, ctx.passkeyOpts(), ctx.authProps());
                if (StringUtils.hasText(url)) {
                    optionsFilter.setRequestMatcher(createPostMatcher(url));
                }
            }

            // PublicKeyCredentialCreationOptionsFilter - registrationOptionsEndpoint
            if (filter instanceof PublicKeyCredentialCreationOptionsFilter creationFilter) {
                String url = flowUrlProvider.getPasskeyRegistrationOptions();
                if (StringUtils.hasText(url)) {
                    creationFilter.setRequestMatcher(createPostMatcher(url));
                }
            }

            // WebAuthnRegistrationFilter - registerEndpoint
            if (filter instanceof WebAuthnRegistrationFilter regFilter) {
                String url = flowUrlProvider.getPasskeyRegistrationProcessing();
                if (StringUtils.hasText(url)) {
                    regFilter.setRegisterCredentialMatcher(createPostMatcher(url));
                }
            }

            // ContexaWebAuthnRegistrationPageFilter - registration page URL
            if (filter instanceof ContexaWebAuthnRegistrationPageFilter pageFilter) {
                String url = flowUrlProvider.getPasskeyRegistrationPage();
                if (StringUtils.hasText(url)) {
                    pageFilter.setRequestMatcher(createGetMatcher(url));
                }
            }
        }
    }

    /**
     * Replace WebAuthn authentication handlers (success/failure).
     */
    public void replaceHandlers(DefaultSecurityFilterChain builtChain,
                                 AuthenticationFlowConfig flowConfig,
                                 ApplicationContext appContext,
                                 boolean isMfaFlow) {

        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter && isWebAuthnAuth(filter)) {
                try {
                    AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
                    StateType stateType = (flowConfig.getStateConfig() != null && flowConfig.getStateConfig().stateType() != null) ?
                            flowConfig.getStateConfig().stateType() : authProps.getStateType();

                    PlatformAuthenticationSuccessHandler successHandler;
                    PlatformAuthenticationFailureHandler failureHandler;

                    if (isMfaFlow) {
                        successHandler = appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                        failureHandler = appContext.getBean(UnifiedAuthenticationFailureHandler.class);
                    } else {
                        if (stateType == StateType.SESSION) {
                            successHandler = null;
                            failureHandler = null;
                        } else {
                            successHandler = appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
                            failureHandler = appContext.getBean(OAuth2SingleAuthFailureHandler.class);
                        }
                    }

                    if (successHandler != null) {
                        authFilter.setAuthenticationSuccessHandler(successHandler);
                    }
                    if (failureHandler != null) {
                        authFilter.setAuthenticationFailureHandler(failureHandler);
                    }
                    return;

                } catch (Exception e) {
                    log.error("Failed to replace WebAuthn handlers for flow: {}", flowConfig.getTypeName(), e);
                }
            }
        }

        log.error("WebAuthnAuthenticationFilter not found in filter chain for flow: {}. " +
                        "Passkey authentication may not work properly without custom handlers.",
                flowConfig.getTypeName());
    }

    /**
     * Replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version.
     */
    public void replaceRegistrationPage(DefaultSecurityFilterChain builtChain, ApplicationContext appContext) {
        try {
            PublicKeyCredentialUserEntityRepository userEntities =
                    appContext.getBean(PublicKeyCredentialUserEntityRepository.class);
            UserCredentialRepository userCredentials =
                    appContext.getBean(UserCredentialRepository.class);

            ContexaWebAuthnRegistrationPageFilter contexaFilter =
                    new ContexaWebAuthnRegistrationPageFilter(userEntities, userCredentials);

            List<Filter> filters = builtChain.getFilters();
            for (int i = 0; i < filters.size(); i++) {
                if (filters.get(i).getClass().getSimpleName().equals("DefaultWebAuthnRegistrationPageGeneratingFilter")) {
                    filters.set(i, contexaFilter);
                    return;
                }
            }
        } catch (Exception e) {
            log.error("Failed to replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version", e);
        }
    }

    private boolean isWebAuthnAuth(Filter filter) {
        String name = filter.getClass().getSimpleName();
        return name.contains("WebAuthn") && !name.contains("Registration");
    }

    private String resolveLoginProcessing(AuthUrlProvider flowProvider, PasskeyOptions opts, AuthContextProperties props) {
        if (flowProvider != null) return flowProvider.getPasskeyLoginProcessing();
        if (opts != null && StringUtils.hasText(opts.getLoginProcessingUrl())) return opts.getLoginProcessingUrl();
        return props.getUrls().getFactors().getPasskey().getLoginProcessing();
    }

    private String resolveAssertionOptions(AuthUrlProvider flowProvider, PasskeyOptions opts, AuthContextProperties props) {
        if (flowProvider != null) return flowProvider.getPasskeyAssertionOptions();
        if (opts != null && StringUtils.hasText(opts.getAssertionOptionsEndpoint())) return opts.getAssertionOptionsEndpoint();
        return props.getUrls().getFactors().getPasskey().getAssertionOptions();
    }

    public record PasskeyCustomizerContext(PasskeyOptions passkeyOpts, AuthContextProperties authProps) {}
}
