package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.adapter.auth.MfaAuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexacommon.enums.AuthType;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Objects;


@Slf4j
public class AuthConfigurerAdapter implements SecurityConfigurer {
    private final AuthenticationAdapter adapter;

    
    public AuthConfigurerAdapter(AuthenticationAdapter adapter) {
        this.adapter = Objects.requireNonNull(adapter, "AuthenticationAdapter cannot be null"); 
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {}

    
    @Override
    public void configure(FlowContext fc) throws Exception {
        Objects.requireNonNull(fc, "FlowContext cannot be null"); 
        Objects.requireNonNull(fc.flow(), "FlowContext.flow cannot be null"); 
        Objects.requireNonNull(fc.http(), "FlowContext.http cannot be null"); 
        

        List<AuthenticationStepConfig> steps = fc.flow().getStepConfigs();

        
        if (adapter instanceof MfaAuthenticationAdapter) {
            
            
            
            if (AuthType.MFA.name().equalsIgnoreCase(fc.flow().getTypeName())) {
                log.debug("Applying MfaAuthenticationAdapter for flow: {}", fc.flow().getTypeName());
                adapter.apply(fc.http(), steps, fc.flow().getStateConfig());

                return; 
            }
        }

        
        if (steps.isEmpty()) { 
            log.trace("No steps configured for flow: {}, adapter: {}", fc.flow().getTypeName(), adapter.getId());
            return;
        }

        boolean applied = false; 
        for (AuthenticationStepConfig step : steps) {
            if (step != null && adapter.getId().equalsIgnoreCase(step.getType())) {
                
                log.info("Applying adapter: {} for step type: {} in flow: {}", adapter.getId(), step.getType(), fc.flow().getTypeName());
                
                adapter.apply(fc.http(), steps, fc.flow().getStateConfig());
                applied = true; 
                
                
                
                
                break; 
            }
        }
        if (!applied) {
            log.info("adapter: {} was not applicable to any step in flow: {}", adapter.getId(), fc.flow().getTypeName());
        }
    }

    @Override
    public int getOrder() {
        
        
        return 300; 
    }
}
