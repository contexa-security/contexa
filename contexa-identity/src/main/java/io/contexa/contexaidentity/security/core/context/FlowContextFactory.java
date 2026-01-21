package io.contexa.contexaidentity.security.core.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.bootstrap.AdapterRegistry;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public class FlowContextFactory {

    private static final Logger log = LoggerFactory.getLogger(FlowContextFactory.class);
    private final AdapterRegistry adapterRegistry;
    private final ApplicationContext applicationContext; 

    public FlowContextFactory(AdapterRegistry adapterRegistry, ApplicationContext applicationContext) {
        this.adapterRegistry = Objects.requireNonNull(adapterRegistry, "featureRegistry cannot be null");
        this.applicationContext = Objects.requireNonNull(applicationContext, "applicationContext cannot be null");
    }

    public List<FlowContext> createAndSortFlows(PlatformConfig config, PlatformContext platformContext) {
        List<FlowContext> flows = new ArrayList<>();
        if (config == null || CollectionUtils.isEmpty(config.getFlows())) {
            log.warn("PlatformConfig or its flows are null/empty. No FlowContexts will be created.");
            return flows;
        }

        for (AuthenticationFlowConfig flowCfg : config.getFlows()) {
            
            HttpSecurity http = platformContext.newHttp();
            
            platformContext.registerHttp(flowCfg, http);

            http.setSharedObject(AuthenticationFlowConfig.class, flowCfg);
            
            http.setSharedObject(PlatformContext.class, platformContext);
            FlowContext fc = new FlowContext(flowCfg, http, platformContext, config);
            setupSharedObjectsForFlow(fc); 
            flows.add(fc);
        }
        flows.sort(Comparator.comparingInt(f -> f.flow().getOrder()));
                return flows;
    }

    private void setupSharedObjectsForFlow(io.contexa.contexaidentity.security.core.context.FlowContext fc) {
        HttpSecurity http = fc.http();
        AuthenticationFlowConfig flowConfig = fc.flow();
        ApplicationContext appContext = this.applicationContext; 

        boolean isMfaFlow = "mfa".equalsIgnoreCase(flowConfig.getTypeName());
        if (isMfaFlow) {
                        
            setSharedObjectIfAbsent(http, MfaPolicyProvider.class, () -> {
                
                MfaPolicyProvider dslProvider = flowConfig.getMfaPolicyProvider();
                if (dslProvider != null) {
                                        return dslProvider;
                }
                
                                return appContext.getBean(MfaPolicyProvider.class);
            });
            setSharedObjectIfAbsent(http, ObjectMapper.class, ObjectMapper::new);
        }
    }
    private <T> void setSharedObjectIfAbsent(HttpSecurity http, Class<T> type, Supplier<T> supplier) {
        if (http.getSharedObject(type) == null) {
            try {
                T object = supplier.get();
                if (object != null) {
                    http.setSharedObject(type, object);
                }
            } catch (Exception e) {
                log.warn("Failed to create/set shared object of type {} for current flow: {}", type.getSimpleName(), e.getMessage());
            }
        }
    }
}