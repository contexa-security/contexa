package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.core.Ordered;

public interface SecurityConfigurer extends Ordered {
    
    void init(PlatformContext ctx, PlatformConfig config);

    void configure(FlowContext fc) throws Exception;

    @Override
    default int getOrder() {
        return 500;  
    }
}

