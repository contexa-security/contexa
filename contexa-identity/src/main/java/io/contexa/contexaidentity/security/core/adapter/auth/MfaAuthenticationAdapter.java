package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.filter.MfaContinuationFilter;
import io.contexa.contexaidentity.security.filter.MfaStepFilterWrapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class MfaAuthenticationAdapter implements AuthenticationAdapter {

    private static final Logger log = LoggerFactory.getLogger(MfaAuthenticationAdapter.class);
    private static final String ID = "mfa";
    private volatile ApplicationContext applicationContext;

    public MfaAuthenticationAdapter() {
        log.error("MfaAuthenticationAdapter created using default constructor. ApplicationContext might not be available.");
    }

    public MfaAuthenticationAdapter(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for MfaAuthenticationAdapter");
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int getOrder() {
        return 10;
    }

    @Override
    public void apply(HttpSecurity http, List<AuthenticationStepConfig> allStepsInCurrentFlow, StateConfig stateConfig) throws Exception {
        AuthenticationFlowConfig currentFlow = http.getSharedObject(AuthenticationFlowConfig.class);

        if (currentFlow == null || !MfaFlowTypeUtils.isMfaFlow(currentFlow.getTypeName())) {
            return;
        }

        if (this.applicationContext == null) {
            synchronized (this) {
                if (this.applicationContext == null) {
                    this.applicationContext = http.getSharedObject(ApplicationContext.class);
                    Assert.notNull(this.applicationContext, "ApplicationContext not found in HttpSecurity sharedObjects and was not provided via constructor.");
                }
            }
        }

        AdapterRegistry adapterRegistry = applicationContext.getBean(AdapterRegistry.class);
        ConfiguredFactorFilterProvider factorFilterProvider = applicationContext.getBean(ConfiguredFactorFilterProvider.class);
        MfaPolicyProvider mfaPolicyProvider = http.getSharedObject(MfaPolicyProvider.class);
        AuthContextProperties authContextProperties = applicationContext.getBean(AuthContextProperties.class);
        AuthResponseWriter responseWriter = applicationContext.getBean(AuthResponseWriter.class);
        EmailOneTimeTokenService emailOttService = null;
        try {
            emailOttService = applicationContext.getBean(EmailOneTimeTokenService.class);
        } catch (Exception e) {
            log.error("EmailOneTimeTokenService bean not found, MfaContinuationFilter will be created without it (some features like OTT challenge initiation might be affected).");
        }

        Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider not found for MFA flow.");
        Assert.notNull(authContextProperties, "AuthContextProperties not found for MFA flow.");
        Assert.notNull(responseWriter, "AuthResponseWriter not found for MFA flow.");
        Assert.notNull(adapterRegistry, "FeatureRegistry bean not found.");

        MfaContinuationFilter mfaContinuationFilter = new MfaContinuationFilter(
                authContextProperties,
                responseWriter,
                applicationContext
        );
        mfaContinuationFilter.setFlowTypeName(currentFlow.getTypeName());

        if (currentFlow.getRegisteredFactorOptions() == null || currentFlow.getRegisteredFactorOptions().isEmpty()) {
            log.error("Critical: MFA flow has no registered factor options");
            throw new IllegalStateException(
                    "MFA initialization failed: No factor options registered. " +
                            "MFA flow requires at least one secondary factor (OTT, Passkey, etc.).");
        }

        AuthUrlProvider flowUrlProvider;
        try {
            MfaFlowUrlRegistry flowUrlRegistry = applicationContext.getBean(MfaFlowUrlRegistry.class);
            flowUrlProvider = flowUrlRegistry.createAndRegister(
                    currentFlow.getTypeName(),
                    currentFlow.getPrimaryAuthenticationOptions(),
                    currentFlow.getRegisteredFactorOptions(),
                    currentFlow.getMfaPageConfig(),
                    currentFlow.getUrlPrefix()
            );

            // Auto-configure securityMatcher when urlPrefix is set
            if (currentFlow.getUrlPrefix() != null) {
                http.securityMatcher(currentFlow.getUrlPrefix() + "/**");
            }

            mfaContinuationFilter.initializeUrlMatchers(flowUrlProvider);
        } catch (Exception e) {
            log.error("Critical: Failed to inject options or initialize URL matchers", e);
            throw new IllegalStateException(
                    "MFA initialization failed: Unable to inject authentication options or initialize URL matchers. " +
                            "MFA flow cannot proceed safely. Please check your configuration.", e);
        }

        http.addFilterBefore(mfaContinuationFilter, LogoutFilter.class);

        // Build factor processing matchers from AuthUrlProvider (prefix-aware)
        List<RequestMatcher> factorProcessingMatchers = new ArrayList<>();
        for (String processingUrl : flowUrlProvider.getAllFactorProcessingUrls()) {
            if (processingUrl != null && !processingUrl.isEmpty()) {
                factorProcessingMatchers.add(
                        PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, processingUrl));
            }
        }

        RequestMatcher mfaFactorProcessingMatcherForWrapper;
        if (factorProcessingMatchers.isEmpty()) {
            log.error("MfaAuthenticationAdapter: No specific factor processing URLs found for MfaStepFilterWrapper in flow '{}'. The wrapper might not match any requests.", currentFlow.getTypeName());
            mfaFactorProcessingMatcherForWrapper = request -> false;
        } else {
            mfaFactorProcessingMatcherForWrapper = new OrRequestMatcher(factorProcessingMatchers);
        }

        MfaStepFilterWrapper mfaStepFilterWrapper =
                new MfaStepFilterWrapper(factorFilterProvider, mfaFactorProcessingMatcherForWrapper,
                        applicationContext, authContextProperties, responseWriter);
        mfaStepFilterWrapper.setFlowTypeName(currentFlow.getTypeName());
        http.addFilterBefore(mfaStepFilterWrapper, LogoutFilter.class);

    }
}

