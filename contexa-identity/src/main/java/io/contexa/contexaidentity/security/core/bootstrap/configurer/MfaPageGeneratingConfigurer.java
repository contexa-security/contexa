package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.exceptionhandling.MfaAuthenticationEntryPoint;
import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.MfaPageConfig;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.Arrays;
import java.util.Collections;

@Slf4j
@Component
public class MfaPageGeneratingConfigurer implements SecurityConfigurer {

    private final ApplicationContext applicationContext;

    public MfaPageGeneratingConfigurer(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void init(PlatformContext platformContext, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext flowContext) {
        AuthenticationFlowConfig flowConfig = flowContext.flow();

        if (!AuthType.MFA.name().equalsIgnoreCase(flowConfig.getTypeName())) {
            log.debug("Skipping MfaPageGeneratingFilter for non-MFA flow: {}", flowConfig.getTypeName());
            return;
        }

        try {
            MfaStateMachineIntegrator stateMachineIntegrator =
                    applicationContext.getBean(MfaStateMachineIntegrator.class);
            AuthUrlProvider authUrlProvider =
                    applicationContext.getBean(AuthUrlProvider.class);

            DefaultMfaPageGeneratingFilter mfaPageFilter = new DefaultMfaPageGeneratingFilter(
                    flowConfig,
                    stateMachineIntegrator,
                    authUrlProvider
            );

            flowContext.http().setSharedObject(DefaultMfaPageGeneratingFilter.class, mfaPageFilter);
            flowContext.http().addFilterBefore(mfaPageFilter, UsernamePasswordAuthenticationFilter.class);

            registerMfaAuthenticationEntryPoint(flowContext, flowConfig);

            String customPagesInfo = buildCustomPagesInfo(flowConfig);
            if (StringUtils.hasText(customPagesInfo)) {
                log.info("Custom pages configured: {}", customPagesInfo);
            }
        } catch (Exception e) {
            log.error(" CRITICAL: Failed to register DefaultMfaPageGeneratingFilter for MFA flow", e);
            throw new RuntimeException("Failed to configure MFA Page Generating Filter", e);
        }
    }

    @Override
    public int getOrder() {
        return SecurityConfigurer.HIGHEST_PRECEDENCE + 150;
    }

    private void registerMfaAuthenticationEntryPoint(FlowContext flowContext, AuthenticationFlowConfig flowConfig) {
        MfaAuthenticationEntryPoint entryPoint = flowConfig.getMfaAuthenticationEntryPoint();

        if (entryPoint == null) {
            throw new IllegalStateException(
                    "MfaAuthenticationEntryPoint is required for MFA flow but was null in flowConfig [" +
                            flowConfig.getTypeName() + "]. " +
                            "This indicates a configuration error in MfaDslConfigurerImpl. " +
                            "Check that primaryAuthenticationOptions is properly configured and EntryPoint is created in build() method."
            );
        }

        try {
            ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
                    (ExceptionHandlingConfigurer<HttpSecurity>)
                            flowContext.http().getConfigurer(ExceptionHandlingConfigurer.class);

            if (exceptionHandling == null) {
                throw new IllegalStateException(
                        "ExceptionHandlingConfigurer not found in HttpSecurity for MFA flow [" +
                                flowConfig.getTypeName() + "]. " +
                                "This indicates a Spring Security configuration issue. " +
                                "Ensure HttpSecurity is properly initialized with exception handling support."
                );
            }

            RequestMatcher entryPointMatcher = createMfaEntryPointMatcher(flowContext);
            exceptionHandling.defaultAuthenticationEntryPointFor(entryPoint, entryPointMatcher);

        } catch (Exception e) {
            log.error(" Failed to register MfaAuthenticationEntryPoint", e);
            throw new RuntimeException("Failed to register MFA AuthenticationEntryPoint", e);
        }
    }

    private RequestMatcher createMfaEntryPointMatcher(FlowContext flowContext) {
        ContentNegotiationStrategy contentNegotiationStrategy =
                flowContext.http().getSharedObject(ContentNegotiationStrategy.class);

        if (contentNegotiationStrategy == null) {
            contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
        }
        MediaTypeRequestMatcher mediaMatcher = new MediaTypeRequestMatcher(
                contentNegotiationStrategy,
                MediaType.APPLICATION_XHTML_XML,
                new MediaType("image", "*"),
                MediaType.TEXT_HTML,
                MediaType.TEXT_PLAIN
        );
        mediaMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
        RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
                new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest")
        );
        return new AndRequestMatcher(Arrays.asList(notXRequestedWith, mediaMatcher));
    }

    private String buildCustomPagesInfo(AuthenticationFlowConfig flowConfig) {
        MfaPageConfig pageConfig = flowConfig.getMfaPageConfig();
        if (pageConfig == null) {
            return "";
        }

        StringBuilder info = new StringBuilder();

        if (pageConfig.hasCustomSelectFactorPage()) {
            info.append("selectFactor=").append(pageConfig.getSelectFactorPageUrl()).append(", ");
        }
        if (pageConfig.hasCustomOttRequestPage()) {
            info.append("ottRequest=").append(pageConfig.getOttRequestPageUrl()).append(", ");
        }
        if (pageConfig.hasCustomOttVerifyPage()) {
            info.append("ottVerify=").append(pageConfig.getOttVerifyPageUrl()).append(", ");
        }
        if (pageConfig.hasCustomPasskeyPage()) {
            info.append("passkey=").append(pageConfig.getPasskeyChallengePageUrl()).append(", ");
        }
        if (pageConfig.hasCustomConfigurePage()) {
            info.append("configure=").append(pageConfig.getConfigurePageUrl()).append(", ");
        }
        if (pageConfig.hasCustomFailurePage()) {
            info.append("failure=").append(pageConfig.getFailurePageUrl());
        }

        String result = info.toString();
        return result.endsWith(", ") ? result.substring(0, result.length() - 2) : result;
    }
}
