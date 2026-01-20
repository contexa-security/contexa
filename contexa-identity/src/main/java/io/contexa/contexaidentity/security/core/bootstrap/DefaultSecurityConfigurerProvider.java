package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.bootstrap.configurer.AuthConfigurerAdapter;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.StateConfigurerAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;


@Slf4j
public final class DefaultSecurityConfigurerProvider implements SecurityConfigurerProvider {

    private final List<SecurityConfigurer> collectedBaseConfigurers;
    private final AdapterRegistry adapterRegistry;

    public DefaultSecurityConfigurerProvider(
            List<SecurityConfigurer> baseConfigurers, 
            AdapterRegistry adapterRegistry,
            ApplicationContext applicationContext) {
        this.collectedBaseConfigurers = (baseConfigurers != null) ? new ArrayList<>(baseConfigurers) : new ArrayList<>();
        this.adapterRegistry = Objects.requireNonNull(adapterRegistry, "FeatureRegistry cannot be null");
        log.info("DefaultSecurityConfigurerProvider initialized with {} base configurers.", this.collectedBaseConfigurers.size());
        if (log.isDebugEnabled()) {
            this.collectedBaseConfigurers.forEach(cfg -> log.debug("  - Detected Base Configurer: {}", cfg.getClass().getName()));
        }
    }

    @Override
    public List<SecurityConfigurer> getGlobalConfigurers(PlatformContext platformContext, PlatformConfig platformConfig) {
        
        
        
        log.debug("DefaultSecurityConfigurerProvider: Providing {} base/global configurers.", collectedBaseConfigurers.size());
        return List.copyOf(this.collectedBaseConfigurers);
    }

    @Override
    public List<SecurityConfigurer> getFlowSpecificConfigurers(
            PlatformContext platformContext,
            PlatformConfig platformConfig,
            HttpSecurity httpForScope) {
        Objects.requireNonNull(httpForScope, "HttpSecurity (httpForScope) cannot be null for getFlowSpecificConfigurers");

        List<SecurityConfigurer> flowSpecificAdapters = new ArrayList<>();
        AuthenticationFlowConfig currentFlow = httpForScope.getSharedObject(AuthenticationFlowConfig.class);

        if (currentFlow == null) {
            log.warn("DefaultSecurityConfigurerProvider: AuthenticationFlowConfig not found in HttpSecurity sharedObjects for hash {}. " +
                            "Cannot determine flow-specific features. No feature adapters will be added for this scope.",
                    httpForScope.hashCode());
            return Collections.emptyList(); 
        }

        log.debug("DefaultSecurityConfigurerProvider: Determining flow-specific configurer adapters for flow '{}' (HttpSecurity hash: {})",
                currentFlow.getTypeName(), httpForScope.hashCode());

        
        if (adapterRegistry != null) {
            
            List<AuthenticationFlowConfig> singleFlowList = Collections.singletonList(currentFlow);

            adapterRegistry.getAuthAdaptersFor(singleFlowList)
                    .forEach(authAdapter -> {
                        flowSpecificAdapters.add(new AuthConfigurerAdapter(authAdapter));
                        log.debug("  Added AuthFeatureConfigurerAdapter for authAdapter '{}' relevant to flow '{}'.",
                                authAdapter.getId(), currentFlow.getTypeName());
                    });

            adapterRegistry.getStateAdaptersFor(singleFlowList)
                    .forEach(stateAdapter -> {
                        flowSpecificAdapters.add(new StateConfigurerAdapter(stateAdapter, platformContext));
                        log.debug("  Added StateFeatureConfigurerAdapter for state feature '{}' relevant to flow '{}'.",
                                stateAdapter.getId(), currentFlow.getTypeName());
                    });
        } else {
            log.warn("DefaultSecurityConfigurerProvider: FeatureRegistry is null. Cannot add feature-based adapters for flow '{}'.", currentFlow.getTypeName());
        }

        log.debug("DefaultSecurityConfigurerProvider: Providing {} flow-specific configurer adapters for flow '{}'.",
                flowSpecificAdapters.size(), currentFlow.getTypeName());
        return List.copyOf(flowSpecificAdapters);
    }
}
