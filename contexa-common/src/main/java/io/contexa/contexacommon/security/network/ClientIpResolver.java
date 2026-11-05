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
package io.contexa.contexacommon.security.network;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;

public final class ClientIpResolver {

    private static final Logger log = LoggerFactory.getLogger(ClientIpResolver.class);
    private static final String FORWARDED_FOR = "X-Forwarded-For";
    private static final Pattern IPV4_ADDRESS = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern IPV6_ADDRESS = Pattern.compile("[0-9a-fA-F.]*:[0-9a-fA-F:.]*");
    private static final List<String> LEGACY_FORWARDED_HEADERS = List.of(
            "X-Forwarded-For",
            "X-Real-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
    );

    private ClientIpResolver() {
    }

    public static String resolve(HttpServletRequest request, ClientIpResolutionPolicy policy) {
        if (request == null) {
            return null;
        }
        ClientIpResolutionPolicy effectivePolicy = policy != null
                ? policy
                : ClientIpResolutionPolicy.legacyForwardedHeaders();

        if (!effectivePolicy.trustedProxyValidationEnabled()) {
            return resolveLegacy(request);
        }

        String remoteAddr = request.getRemoteAddr();
        List<String> trustedProxies = effectivePolicy.trustedProxies();
        if (trustedProxies == null || trustedProxies.isEmpty()) {
            return remoteAddr;
        }
        if (!isTrustedProxy(remoteAddr, trustedProxies)) {
            return remoteAddr;
        }

        String forwardedFor = clientBehindProxies(request, trustedProxies);
        if (forwardedFor != null) {
            return forwardedFor;
        }

        String realIp = firstHeaderValue(request.getHeader("X-Real-IP"));
        return hasUsableText(realIp) ? realIp : remoteAddr;
    }

    public static String resolveLegacy(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        for (String header : LEGACY_FORWARDED_HEADERS) {
            String clientIp = firstHeaderValue(request.getHeader(header));
            if (hasUsableText(clientIp)) {
                return clientIp;
            }
        }
        return request.getRemoteAddr();
    }

    public static boolean isTrustedProxy(String ip, List<String> trustedProxies) {
        if (!hasUsableText(ip) || trustedProxies == null) {
            return false;
        }

        for (String trusted : trustedProxies) {
            if (!hasUsableText(trusted)) {
                continue;
            }
            String normalizedTrusted = trusted.trim();
            try {
                if (normalizedTrusted.contains("/")) {
                    if (isIpInCidr(ip, normalizedTrusted)) {
                        return true;
                    }
                } else if (normalizedTrusted.equals(ip.trim())) {
                    return true;
                }
            } catch (Exception e) {
                log.error("[ClientIpResolver] Invalid trusted proxy format: {}", normalizedTrusted, e);
            }
        }

        return false;
    }

    /**
     * The client a chain of proxies names. Each proxy adds the address it saw to the end of the list, so what a client
     * wrote itself stays on the left: the list is read from its end, past the trusted proxies, up to the first address
     * that is not one. What stands before that address proves nothing.
     */
    private static String clientBehindProxies(HttpServletRequest request, List<String> trustedProxies) {
        List<String> hops = forwardedHops(request);
        String client = null;
        for (int index = hops.size() - 1; index >= 0; index--) {
            String address = addressOf(hops.get(index));
            if (address == null) {
                break;
            }
            client = address;
            if (!isTrustedProxy(address, trustedProxies)) {
                break;
            }
        }
        return client;
    }

    /** Every line of the header in order: a proxy may add a line of its own instead of joining the client's. */
    private static List<String> forwardedHops(HttpServletRequest request) {
        List<String> lines = new ArrayList<>();
        Enumeration<String> values = request.getHeaders(FORWARDED_FOR);
        if (values != null) {
            while (values.hasMoreElements()) {
                lines.add(values.nextElement());
            }
        } else if (request.getHeader(FORWARDED_FOR) != null) {
            lines.add(request.getHeader(FORWARDED_FOR));
        }
        List<String> hops = new ArrayList<>();
        for (String line : lines) {
            for (String hop : line.split(",")) {
                hops.add(hop.trim());
            }
        }
        return hops;
    }

    /** The address of a hop without its port, or null when it is no address: a name would send the check to the DNS. */
    private static String addressOf(String hop) {
        String address = hop;
        if (address.startsWith("[") && address.indexOf(']') > 0) {
            address = address.substring(1, address.indexOf(']'));
        } else if (address.indexOf(':') > 0 && address.indexOf(':') == address.lastIndexOf(':')) {
            address = address.substring(0, address.indexOf(':'));
        }
        return IPV4_ADDRESS.matcher(address).matches() || IPV6_ADDRESS.matcher(address).matches() ? address : null;
    }

    private static String firstHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        String candidate = value;
        if (candidate.contains(",")) {
            candidate = candidate.split(",", 2)[0];
        }
        return candidate.trim();
    }

    private static boolean hasUsableText(String value) {
        return value != null && !value.isBlank() && !"unknown".equalsIgnoreCase(value.trim());
    }

    private static boolean isIpInCidr(String ip, String cidr) throws Exception {
        String[] parts = cidr.split("/", 2);
        if (parts.length != 2) {
            return false;
        }

        InetAddress inetIp = InetAddress.getByName(ip.trim());
        InetAddress inetNetwork = InetAddress.getByName(parts[0].trim());
        byte[] ipBytes = inetIp.getAddress();
        byte[] networkBytes = inetNetwork.getAddress();
        if (ipBytes.length != networkBytes.length) {
            return false;
        }

        int prefixLength = Integer.parseInt(parts[1].trim());
        int maxPrefixLength = ipBytes.length * 8;
        if (prefixLength < 0 || prefixLength > maxPrefixLength) {
            return false;
        }

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (ipBytes[i] != networkBytes[i]) {
                return false;
            }
        }

        if (remainingBits == 0) {
            return true;
        }

        int mask = (0xFF << (8 - remainingBits)) & 0xFF;
        return ((ipBytes[fullBytes] ^ networkBytes[fullBytes]) & mask) == 0;
    }
}
