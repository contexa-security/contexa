/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.llm.gate;

import java.net.URI;
import java.util.Locale;

/**
 * A model server: the provider and the address its calls go to. Calls to one address share one gate, whichever model
 * they ask for. A self-hosted server (Ollama, or any address on this host or a private network) runs few calls at once
 * and loads its models in turn; a remote provider takes many.
 *
 * @param provider   the provider, such as ollama, openai or anthropic
 * @param address    scheme, host and port of the server, or null when the address is not known
 * @param selfHosted whether the server runs on this host or a private network
 */
public record ModelServer(String provider, String address, boolean selfHosted) {

    public static ModelServer of(String provider, String baseUrl) {
        String normalizedProvider = provider != null && !provider.isBlank()
                ? provider.trim().toLowerCase(Locale.ROOT) : "unknown";
        String address = normalizeAddress(baseUrl);
        boolean selfHosted = "ollama".equals(normalizedProvider) || isSelfHostedAddress(address);
        return new ModelServer(normalizedProvider, address, selfHosted);
    }

    /** The key of the server's gate: the provider and the address. */
    public String key() {
        return address != null ? provider + "@" + address : provider;
    }

    /** Scheme, host and port, lower case, with the scheme's port filled in; null when it cannot be read. */
    public static String normalizeAddress(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(baseUrl.trim());
            if (uri.getHost() == null) {
                return null;
            }
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "http";
            int port = uri.getPort() > 0 ? uri.getPort() : ("https".equals(scheme) ? 443 : 80);
            return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + ":" + port;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    /**
     * Whether the address is this host, a private network, or a name only a local network resolves (a container
     * name, host.docker.internal, a .local or .internal name).
     */
    static boolean isSelfHostedAddress(String address) {
        if (address == null) {
            return false;
        }
        String host = URI.create(address).getHost();
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        if (host.contains(":")) {
            // IPv6: the loopback, a unique local (fc00::/7) or a link-local (fe80::/10) address.
            return host.equals("::1") || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:");
        }
        if (host.equals("localhost") || host.equals("0.0.0.0") || host.startsWith("127.")
                || host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")
                || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")) {
            return true;
        }
        if (host.startsWith("172.")) {
            String[] parts = host.split("\\.");
            if (parts.length == 4) {
                try {
                    int second = Integer.parseInt(parts[1]);
                    return second >= 16 && second <= 31;
                } catch (NumberFormatException ignored) {
                    return false;
                }
            }
        }
        // A name without a dot (a container or service name) resolves only on a local network.
        return !host.contains(".");
    }
}
