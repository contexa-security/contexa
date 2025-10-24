package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.MfaContinuationFilter;
import io.contexa.contexaidentity.security.filter.MfaStepFilterWrapper;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
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
    private ApplicationContext applicationContext; // 생성자 주입으로 변경 권장

    public MfaAuthenticationAdapter() {
        log.warn("MfaAuthenticationAdapter created using default constructor. ApplicationContext might not be available.");
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

        if (currentFlow == null || !ID.equalsIgnoreCase(currentFlow.getTypeName())) {
            log.trace("MfaAuthenticationAdapter.apply() called, but current flow is not 'mfa' or FlowConfig not shared. Skipping MFA common filter setup.");
            return;
        }

        log.info("MfaAuthenticationAdapter: Applying MFA common filters for flow '{}'.", currentFlow.getTypeName());

        // ApplicationContext가 생성자에서 주입되지 않았다면 HttpSecurity의 공유 객체에서 가져오기 시도
        if (this.applicationContext == null) {
            this.applicationContext = http.getSharedObject(ApplicationContext.class);
            Assert.notNull(this.applicationContext, "ApplicationContext not found in HttpSecurity sharedObjects and was not provided via constructor.");
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
            log.warn("EmailOneTimeTokenService bean not found, MfaContinuationFilter will be created without it (some features like OTT challenge initiation might be affected).");
        }

        Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider not found for MFA flow.");
        Assert.notNull(authContextProperties, "AuthContextProperties not found for MFA flow.");
        Assert.notNull(responseWriter, "AuthResponseWriter not found for MFA flow.");
        Assert.notNull(adapterRegistry, "FeatureRegistry bean not found.");

        MfaContinuationFilter mfaContinuationFilter = new MfaContinuationFilter(
                mfaPolicyProvider,
                authContextProperties,
                responseWriter,
                applicationContext
        );
        http.addFilterBefore(mfaContinuationFilter, LogoutFilter.class);

        // MfaStepFilterWrapper에 필요한 RequestMatcher 생성
        List<RequestMatcher> factorProcessingMatchers = new ArrayList<>();
        if (currentFlow.getStepConfigs() != null) {
            for (AuthenticationStepConfig step : currentFlow.getStepConfigs()) {
                // 1차 인증 단계(order 0)는 제외하고, 2차 인증 요소들의 처리 URL만 포함
                if (step.getOrder() > 0) {
                    Object optionsObj = step.getOptions().get("_options");
                    if (optionsObj instanceof AuthenticationProcessingOptions procOpts) {
                        String processingUrl = procOpts.getLoginProcessingUrl();
                        if (processingUrl != null) {
                            // 일반적으로 MFA Factor 검증은 POST 요청
                            factorProcessingMatchers.add(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, processingUrl));
                            log.debug("MfaAuthenticationAdapter: Added AntPathRequestMatcher for MFA factor processing URL: POST {}", processingUrl);
                        }
                    }
                }
            }
        }

        RequestMatcher mfaFactorProcessingMatcherForWrapper;
        if (factorProcessingMatchers.isEmpty()) {
            log.warn("MfaAuthenticationAdapter: No specific factor processing URLs found for MfaStepFilterWrapper in flow '{}'. The wrapper might not match any requests.", currentFlow.getTypeName());
            // 매칭할 URL이 없으면 어떤 요청도 처리하지 않도록 설정
            mfaFactorProcessingMatcherForWrapper = request -> false;
        } else {
            mfaFactorProcessingMatcherForWrapper = new OrRequestMatcher(factorProcessingMatchers);
        }

        MfaStepFilterWrapper mfaStepFilterWrapper =
                new MfaStepFilterWrapper(factorFilterProvider, mfaFactorProcessingMatcherForWrapper,
                                         applicationContext, authContextProperties, responseWriter);
        http.addFilterBefore(mfaStepFilterWrapper, LogoutFilter.class);

        log.debug("MFA common filters (MfaContinuationFilter, MfaStepFilterWrapper) added for MFA flow.");
    }
}

