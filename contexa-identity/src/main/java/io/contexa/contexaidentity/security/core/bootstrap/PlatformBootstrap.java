/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.validator.DslValidator;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;

import java.util.List;

@Slf4j
public class PlatformBootstrap implements InitializingBean {

    private final SecurityPlatform platform;
    private final PlatformConfig config;
    private final AdapterRegistry registry;
    private final DslValidator dslValidator;
    private final BridgeProperties bridgeProperties;

    public PlatformBootstrap(SecurityPlatform platform, PlatformConfig config,
                             AdapterRegistry registry, DslValidator dslValidator) {
        this(platform, config, registry, dslValidator, null);
    }

    public PlatformBootstrap(SecurityPlatform platform, PlatformConfig config,
                             AdapterRegistry registry, DslValidator dslValidator,
                             BridgeProperties bridgeProperties) {
        this.platform = platform;
        this.config = config;
        this.registry = registry;
        this.dslValidator = dslValidator;
        this.bridgeProperties = bridgeProperties;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        try {
            dslValidator.validate(config);
        } catch (DslConfigurationException e) {
            log.error("Server startup aborted due to DSL validation failure.", e);
            throw e;
        }

        if (bridgeProperties != null && !bridgeProperties.isContexaOwned()) {
            log.info("Skipping Contexa-owned authentication chain bootstrap in HOST_OWNED mode");
            return;
        }

        List<AuthenticationFlowConfig> flows = config.getFlows();
        List<AuthenticationAdapter> adapters = registry.getAuthAdaptersFor(flows);
        platform.prepareGlobal(config, adapters);
        platform.initialize();
    }
}
