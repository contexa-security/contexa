package io.contexa.contexacommon.security.network;

import java.util.List;

public record ClientIpResolutionPolicy(
        boolean trustedProxyValidationEnabled,
        List<String> trustedProxies) {

    public ClientIpResolutionPolicy {
        trustedProxies = trustedProxies != null ? List.copyOf(trustedProxies) : List.of();
    }

    public static ClientIpResolutionPolicy of(boolean trustedProxyValidationEnabled, List<String> trustedProxies) {
        return new ClientIpResolutionPolicy(trustedProxyValidationEnabled, trustedProxies);
    }

    public static ClientIpResolutionPolicy trustedProxy(List<String> trustedProxies) {
        return new ClientIpResolutionPolicy(true, trustedProxies);
    }

    public static ClientIpResolutionPolicy legacyForwardedHeaders() {
        return new ClientIpResolutionPolicy(false, List.of());
    }
}
