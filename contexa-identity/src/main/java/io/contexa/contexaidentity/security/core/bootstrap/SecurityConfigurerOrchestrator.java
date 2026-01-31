package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public final class SecurityConfigurerOrchestrator {

    private final SecurityConfigurerProvider configurerProvider;

    public SecurityConfigurerOrchestrator(SecurityConfigurerProvider configurerProvider) {
        this.configurerProvider = Objects.requireNonNull(configurerProvider, "SecurityConfigurerProvider cannot be null");
    }

    public void applyConfigurations(
            List<FlowContext> flows,
            PlatformContext platformContext,
            PlatformConfig platformConfig) throws Exception {

        Objects.requireNonNull(flows, "Flows list cannot be null");
        Objects.requireNonNull(platformContext, "PlatformContext cannot be null");
        Objects.requireNonNull(platformConfig, "PlatformConfig cannot be null");

        List<SecurityConfigurer> globalConfigurers = configurerProvider.getGlobalConfigurers(platformContext, platformConfig);
        if (globalConfigurers == null) {
            globalConfigurers = Collections.emptyList();
        }
        for (SecurityConfigurer cfg : globalConfigurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .toList()) {
            try {
                cfg.init(platformContext, platformConfig);
            } catch (Exception e) {
                String errorMsg = "Error during global SecurityConfigurer initialization: " + cfg.getClass().getSimpleName();
                log.error(errorMsg, e);
                throw new RuntimeException(errorMsg, e);
            }
        }

        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null");
            HttpSecurity currentHttpSecurity = Objects.requireNonNull(fc.http(), "HttpSecurity in FlowContext cannot be null");
            String flowTypeName = Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null").getTypeName();

            platformContext.share(FlowContext.class, fc);

            List<SecurityConfigurer> flowSpecificAdapters = configurerProvider.getFlowSpecificConfigurers(
                    platformContext, platformConfig, currentHttpSecurity
            );
            if (flowSpecificAdapters == null) {
                flowSpecificAdapters = Collections.emptyList();
            }

            List<SecurityConfigurer> finalConfigurersForFlow = new ArrayList<>();
            finalConfigurersForFlow.addAll(globalConfigurers);
            finalConfigurersForFlow.addAll(flowSpecificAdapters);

            finalConfigurersForFlow = finalConfigurersForFlow.stream()
                    .distinct()
                    .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                    .collect(Collectors.toList());

            for (SecurityConfigurer cfg : finalConfigurersForFlow) {
                try {
                    cfg.configure(fc);
                } catch (Exception e) {
                    String errorMessage = String.format(
                            "Error applying SecurityConfigurer '%s' for flow '%s'.",
                            cfg.getClass().getSimpleName(), flowTypeName
                    );
                    log.error(errorMessage, e);
                    throw new RuntimeException(errorMessage, e);
                }
            }
        }
    }
}
