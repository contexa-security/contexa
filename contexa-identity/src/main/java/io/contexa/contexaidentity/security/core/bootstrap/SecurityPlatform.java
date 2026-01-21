package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;

import java.util.List;

public interface SecurityPlatform {

    void prepareGlobal(PlatformConfig config, List<?> features);

    void initialize() throws Exception;
}