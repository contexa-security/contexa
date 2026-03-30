package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.web.context.SecurityContextRepository;

public class SessionSecurityContextRepositoryConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 105;

    private final AISessionSecurityContextRepository aiSessionSecurityContextRepository;

    public SessionSecurityContextRepositoryConfigurer(
            AISessionSecurityContextRepository aiSessionSecurityContextRepository) {
        this.aiSessionSecurityContextRepository = aiSessionSecurityContextRepository;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // no-op
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (aiSessionSecurityContextRepository == null) {
            return;
        }
        fc.http().securityContext(sc -> sc.securityContextRepository(aiSessionSecurityContextRepository));
        fc.http().setSharedObject(SecurityContextRepository.class, aiSessionSecurityContextRepository);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
