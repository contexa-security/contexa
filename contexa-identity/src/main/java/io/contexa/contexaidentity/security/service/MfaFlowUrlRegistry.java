package io.contexa.contexaidentity.security.service;

import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaPageConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for per-flow AuthUrlProvider instances.
 * Each MFA flow gets its own AuthUrlProvider to avoid shared mutable state.
 */
@Slf4j
public class MfaFlowUrlRegistry {

    private final Map<String, AuthUrlProvider> flowProviders = new ConcurrentHashMap<>();
    private final AuthContextProperties properties;

    public MfaFlowUrlRegistry(AuthContextProperties properties) {
        this.properties = properties;
    }

    /**
     * Creates and registers a per-flow AuthUrlProvider for the given flow.
     * Returns the created provider.
     */
    public AuthUrlProvider createAndRegister(String flowTypeName,
                                              @Nullable PrimaryAuthenticationOptions primaryAuthOptions,
                                              @Nullable Map<AuthType, AuthenticationProcessingOptions> factorOptions,
                                              @Nullable MfaPageConfig mfaPageConfig) {
        return createAndRegister(flowTypeName, primaryAuthOptions, factorOptions, mfaPageConfig, null);
    }

    public AuthUrlProvider createAndRegister(String flowTypeName,
                                              @Nullable PrimaryAuthenticationOptions primaryAuthOptions,
                                              @Nullable Map<AuthType, AuthenticationProcessingOptions> factorOptions,
                                              @Nullable MfaPageConfig mfaPageConfig,
                                              @Nullable String urlPrefix) {

        AuthUrlProvider flowProvider = new AuthUrlProvider(properties);

        if (urlPrefix != null) {
            flowProvider.setUrlPrefix(urlPrefix);
        }
        if (primaryAuthOptions != null) {
            flowProvider.setPrimaryAuthenticationOptions(primaryAuthOptions);
        }
        if (factorOptions != null && !factorOptions.isEmpty()) {
            flowProvider.updateFactorOptions(factorOptions);
        }
        if (mfaPageConfig != null) {
            flowProvider.setMfaPageConfig(mfaPageConfig);
        }

        String key = flowTypeName.toLowerCase();
        flowProviders.put(key, flowProvider);
        return flowProvider;
    }

    /**
     * Gets the AuthUrlProvider for a specific flow.
     * Returns null if no provider is registered for this flow.
     */
    @Nullable
    public AuthUrlProvider getProvider(String flowTypeName) {
        if (flowTypeName == null) {
            return null;
        }
        return flowProviders.get(flowTypeName.toLowerCase());
    }

    /**
     * Returns all MFA page URLs from all registered flows.
     * Used by ZeroTrust filters to identify MFA-related paths.
     */
    public Set<String> getAllMfaPageUrls() {
        Set<String> allUrls = new HashSet<>();
        for (AuthUrlProvider provider : flowProviders.values()) {
            allUrls.addAll(provider.getMfaPageUrls());
        }
        return allUrls;
    }
}
