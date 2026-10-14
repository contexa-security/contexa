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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class SecuritySemanticNormalizer {

    /** The event keys of the URL template the host matched for a protected request, in the order they are read. */
    private static final List<String> TEMPLATE_KEYS = List.of("protectableResourceUrl", "resourceUrlTemplate");
    private static final String ID_SEGMENT = "{id}";
    private static final Pattern VERSION_SEGMENT = Pattern.compile("[vV]\\d+(\\.\\d+)*");
    private static final Pattern UUID_SEGMENT =
            Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern HEX_SEGMENT = Pattern.compile("[0-9a-fA-F]+");
    /** Words a client gives for a device class or for no value; none of them names an operating system. */
    private static final Set<String> NOT_OPERATING_SYSTEMS =
            Set.of("DESKTOP", "MOBILE", "TABLET", "UNKNOWN", "OTHER", "NONE", "NA", "N/A", "NULL");
    /** Every word {@link #classificationLevel} reads as a class, and UNKNOWN. */
    private static final Set<String> CLASS_WORDS = Set.of("CRITICAL", "RESTRICTED", "SENSITIVE", "HIGH", "CONFIDENTIAL",
            "SECRET", "NORMAL", "MEDIUM", "INTERNAL", "STANDARD", "PUBLIC", "LOW", "UNKNOWN");
    private static final String DEVICE_SYSTEM_SEPARATOR = " on ";

    private SecuritySemanticNormalizer() {
    }

    public static String normalizeAuthenticationType(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            if (containsAny(candidate, "PASSKEY", "WEBAUTHN", "FIDO")) {
                return "PASSKEY";
            }
            if (containsAny(candidate, "SAML", "OIDC", "OAUTH", "SSO")) {
                return "SSO";
            }
            if (containsAny(candidate, "USERNAMEPASSWORD", "PASSWORD")) {
                return "PASSWORD";
            }
            // A one-time code or recovery code login; checked before TOKEN so that it is not read as an API token.
            if (containsAny(candidate, "ONE_TIME_CODE", "RECOVERY_CODE")) {
                return "ONE_TIME_CODE";
            }
            if (containsAny(candidate, "SESSION", "SECURITY_CONTEXT")) {
                return "SESSION";
            }
            if (containsAny(candidate, "BEARER", "JWT", "APIKEY", "TOKEN")) {
                return "TOKEN";
            }
            if (containsAny(candidate, "MFA", "TOTP", "OTP")) {
                return "MFA_ONLY";
            }
            if ("UNKNOWN".equals(candidate) || containsAny(candidate, "ANONYMOUS", "UNAUTHENTICATED")) {
                return "UNKNOWN";
            }
        }
        return null;
    }

    /** The {@link ActionFamily} name of the first value that names one, by whole words; null when none does. */
    public static String normalizeActionFamily(Object... rawValues) {
        ActionFamily family = ActionFamily.firstOf(rawValues);
        return family != null ? family.name() : null;
    }

    /**
     * The resource class (CRITICAL, SENSITIVE, NORMAL, PUBLIC) of the first value that names one. Only classification
     * values belong here (sensitivity, resource type, an already normalized class): callers never pass business labels,
     * paths, categories or other free text, because a word inside such text is not a classification.
     */
    public static String normalizeResourceClass(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String level = classificationLevel(rawValue);
            if (level != null) {
                return level;
            }
        }
        return null;
    }

    /**
     * The resource's class: the context's own field, else the classification values the resource holds (sensitivity,
     * then type). A category never decides a class.
     */
    public static String resourceClassOf(CanonicalSecurityContext.Resource resource) {
        if (resource == null) {
            return null;
        }
        if (StringUtils.hasText(resource.getResourceClass())) {
            return resource.getResourceClass();
        }
        return normalizeResourceClass(resource.getSensitivity(), resource.getResourceType());
    }

    /**
     * What kind of business resource the first value names (REPORT, AUDIT_LOG, PROJECT_DOCUMENTS), as a token. A value
     * made only of class words (CRITICAL, HIGH, PUBLIC, ...) names a class, not a category, and is passed over: the role
     * scope and the delegated scope compare categories, where a class word would be compared as one.
     */
    public static String normalizeResourceCategory(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (StringUtils.hasText(candidate) && !classWordsOnly(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean classWordsOnly(String candidate) {
        boolean anyWord = false;
        for (String word : candidate.split("[^A-Z0-9]+")) {
            if (word.isEmpty()) {
                continue;
            }
            if (!CLASS_WORDS.contains(word)) {
                return false;
            }
            anyWord = true;
        }
        return anyWord;
    }

    /** The same classification as {@link #normalizeResourceClass} on the sensitivity scale (CRITICAL, HIGH, MEDIUM, LOW). */
    public static String normalizeSensitivity(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String level = classificationLevel(rawValue);
            if (level != null) {
                return switch (level) {
                    case "SENSITIVE" -> "HIGH";
                    case "NORMAL" -> "MEDIUM";
                    case "PUBLIC" -> "LOW";
                    default -> level;
                };
            }
        }
        return null;
    }

    /**
     * One vocabulary for both scales, matched as whole words. RESTRICTED is the top level of the common four-level
     * classification (public, internal, confidential, restricted), above CONFIDENTIAL.
     */
    private static String classificationLevel(Object rawValue) {
        String candidate = normalizeToken(rawValue);
        if (!StringUtils.hasText(candidate)) {
            return null;
        }
        if ("UNKNOWN".equals(candidate)) {
            return "UNKNOWN";
        }
        Set<String> words = new HashSet<>(Arrays.asList(candidate.split("[^A-Z0-9]+")));
        if (containsWord(words, "CRITICAL", "RESTRICTED")) {
            return "CRITICAL";
        }
        if (containsWord(words, "SENSITIVE", "HIGH", "CONFIDENTIAL", "SECRET")) {
            return "SENSITIVE";
        }
        if (containsWord(words, "NORMAL", "MEDIUM", "INTERNAL", "STANDARD")) {
            return "NORMAL";
        }
        if (containsWord(words, "PUBLIC", "LOW")) {
            return "PUBLIC";
        }
        return null;
    }

    private static boolean containsWord(Set<String> words, String... vocabulary) {
        for (String word : vocabulary) {
            if (words.contains(word)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The path family of a request: the URL template the host matched ({@code protectableResourceUrl}, then
     * {@code resourceUrlTemplate}) when it gave one, else the request path with its identifier segments generalized.
     */
    public static String pathFamilyOf(Map<String, ?> metadata, String rawPath) {
        if (metadata != null) {
            for (String key : TEMPLATE_KEYS) {
                Object template = metadata.get(key);
                if (template != null && StringUtils.hasText(template.toString())) {
                    return normalizePathFamily(template.toString());
                }
            }
        }
        return normalizePathFamily(rawPath);
    }

    /**
     * The path family of a path. A URL template (a value with a {@code {variable}} segment) is kept whole, as the
     * host declared it. Any other path has each segment shaped like an identifier replaced by {@code {id}} and is cut
     * after its fourth segment. Normalizing a path family again gives the same value, so stored and current values
     * compare under one rule.
     */
    public static String normalizePathFamily(String rawPath) {
        if (!StringUtils.hasText(rawPath)) {
            return null;
        }
        String path = rawPath.trim();
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) {
            path = path.substring(0, queryIndex);
        }
        List<String> segments = new ArrayList<>();
        for (String segment : path.split("/")) {
            if (StringUtils.hasText(segment)) {
                segments.add(segment);
            }
        }
        if (segments.stream().anyMatch(SecuritySemanticNormalizer::isTemplateVariable)) {
            return "/" + String.join("/", segments);
        }
        StringBuilder normalized = new StringBuilder();
        int appendedSegments = 0;
        for (String segment : segments) {
            normalized.append('/').append(isIdentifier(segment) ? ID_SEGMENT : segment);
            appendedSegments++;
            if (appendedSegments >= 4) {
                normalized.append("/*");
                return normalized.toString();
            }
        }
        return normalized.length() == 0 ? "/" : normalized.toString();
    }

    private static boolean isTemplateVariable(String segment) {
        return segment.length() > 2 && segment.startsWith("{") && segment.endsWith("}");
    }

    /**
     * Whether a path segment names one instance rather than a kind of resource: digits only, a UUID, a long hex value,
     * letters and digits joined by a separator (GB-500, HX-310-DWG-00001) or a word with four or more digits. A version
     * segment (v1, v2.1) and a segment without digits are kept.
     */
    private static boolean isIdentifier(String segment) {
        if (VERSION_SEGMENT.matcher(segment).matches()) {
            return false;
        }
        int digits = 0;
        boolean letters = false;
        boolean separator = false;
        for (char c : segment.toCharArray()) {
            if (Character.isDigit(c)) {
                digits++;
            } else if (Character.isLetter(c)) {
                letters = true;
            } else if (c == '-' || c == '_' || c == '.') {
                separator = true;
            }
        }
        if (digits == 0) {
            return false;
        }
        return digits == segment.length()
                || UUID_SEGMENT.matcher(segment).matches()
                || (segment.length() >= 16 && HEX_SEGMENT.matcher(segment).matches())
                || (letters && separator)
                || digits >= 4;
    }

    /**
     * Whether two network values name the same network. Learned baselines and memory documents written before W2-4
     * hold the three-octet prefix ({@code a.b.c}) where the request now carries the band ({@code a.b.c.0/24}); both
     * forms of the same /24 compare equal. Other values compare as written, ignoring case, so an address is not its
     * band.
     */
    public static boolean sameNetwork(String left, String right) {
        String leftKey = networkKey(left);
        String rightKey = networkKey(right);
        return leftKey != null && leftKey.equals(rightKey);
    }

    private static String networkKey(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String text = value.trim().toLowerCase(Locale.ROOT);
        if (text.endsWith(".0/24")) {
            String prefix = text.substring(0, text.length() - ".0/24".length());
            if (isThreeOctetPrefix(prefix)) {
                return prefix;
            }
        }
        return text;
    }

    private static boolean isThreeOctetPrefix(String text) {
        String[] octets = text.split("\\.", -1);
        if (octets.length != 3) {
            return false;
        }
        for (String octet : octets) {
            if (!isOctet(octet)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isOctet(String text) {
        return !text.isEmpty() && text.length() <= 3 && text.chars().allMatch(Character::isDigit)
                && Integer.parseInt(text) <= 255;
    }

    /**
     * The network of a request in one form (W2-4, B-10): the IPv4 /24 band ({@code 10.40.12.0/24}) or the IPv6 /64
     * prefix ({@code 2001:db8:0:1::/64}). A band the host gives keeps its own length; a three-octet prefix, the form
     * learned baselines stored before, reads as its /24 band. Without a band, the band of the address; an address that
     * is neither IPv4 nor IPv6 gives no network.
     */
    public static String normalizeNetwork(String sourceIp, String ipBand) {
        if (StringUtils.hasText(ipBand)) {
            String band = band(ipBand.trim().toLowerCase(Locale.ROOT));
            return band != null ? band : ipBand.trim();
        }
        return StringUtils.hasText(sourceIp) ? band(sourceIp.trim().toLowerCase(Locale.ROOT)) : null;
    }

    private static String band(String text) {
        if (text.contains("/")) {
            return text;
        }
        if (isThreeOctetPrefix(text)) {
            return text + ".0/24";
        }
        int lastDot = text.lastIndexOf('.');
        if (lastDot > 0 && isThreeOctetPrefix(text.substring(0, lastDot)) && isOctet(text.substring(lastDot + 1))) {
            return text.substring(0, lastDot) + ".0/24";
        }
        return ipv6Prefix(text);
    }

    /** The /64 prefix of an IPv6 address with its groups written without leading zeros, null when it is not one. */
    private static String ipv6Prefix(String text) {
        int zone = text.indexOf('%');
        String address = zone >= 0 ? text.substring(0, zone) : text;
        if (!address.contains(":")) {
            return null;
        }
        int gap = address.indexOf("::");
        if (gap != address.lastIndexOf("::")) {
            return null;
        }
        List<String> groups = new ArrayList<>();
        if (gap >= 0) {
            List<String> head = ipv6Groups(address.substring(0, gap));
            List<String> tail = ipv6Groups(address.substring(gap + 2));
            if (head == null || tail == null || head.size() + tail.size() > 7) {
                return null;
            }
            groups.addAll(head);
            for (int index = head.size() + tail.size(); index < 8; index++) {
                groups.add("0");
            }
            groups.addAll(tail);
        } else {
            List<String> all = ipv6Groups(address);
            if (all == null || all.size() != 8) {
                return null;
            }
            groups.addAll(all);
        }
        return String.join(":", groups.subList(0, 4)) + "::/64";
    }

    private static List<String> ipv6Groups(String text) {
        if (text.isEmpty()) {
            return List.of();
        }
        List<String> groups = new ArrayList<>();
        for (String group : text.split(":", -1)) {
            if (group.isEmpty() || group.length() > 4 || !HEX_SEGMENT.matcher(group).matches()) {
                return null;
            }
            groups.add(Integer.toHexString(Integer.parseInt(group, 16)));
        }
        return groups;
    }

    /**
     * The operating system in one vocabulary (W2-4, B-10): WINDOWS, MAC, IOS, ANDROID, CHROMEOS or LINUX, else the
     * name as an upper-case word. A word that names no operating system (a device class such as DESKTOP, or UNKNOWN)
     * gives no value, so that an unknown system is not stated as one.
     */
    public static String normalizeOperatingSystem(Object... rawValues) {
        for (Object rawValue : rawValues) {
            String candidate = normalizeToken(rawValue);
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            String compact = candidate.replace("_", "");
            if (compact.startsWith("WINDOWS") || compact.equals("WIN") || compact.equals("WIN32")
                    || compact.equals("WIN64")) {
                return "WINDOWS";
            }
            if (compact.startsWith("MAC") || compact.equals("OSX") || compact.equals("DARWIN")) {
                return "MAC";
            }
            if (compact.startsWith("IOS") || compact.startsWith("IPADOS") || compact.startsWith("IPHONE")
                    || compact.startsWith("IPAD")) {
                return "IOS";
            }
            if (compact.startsWith("ANDROID")) {
                return "ANDROID";
            }
            if (compact.startsWith("CHROMEOS") || compact.equals("CROS")) {
                return "CHROMEOS";
            }
            if (compact.startsWith("LINUX")) {
                return "LINUX";
            }
            if (NOT_OPERATING_SYSTEMS.contains(compact)) {
                continue;
            }
            return candidate;
        }
        return null;
    }

    /**
     * One device: the browser with its version on the operating system ({@code Chrome/140 on WINDOWS}), the browser
     * alone when the system is unknown, and no device without a browser.
     */
    public static String device(String browser, String operatingSystem) {
        if (!StringUtils.hasText(browser)) {
            return null;
        }
        String system = normalizeOperatingSystem(operatingSystem);
        return system == null ? browser.trim() : browser.trim() + DEVICE_SYSTEM_SEPARATOR + system;
    }

    /**
     * Whether the observed devices hold the current one. A device whose system is unknown is held by any device of
     * the same browser.
     */
    public static boolean deviceSeen(List<String> observedDevices, String currentDevice) {
        if (observedDevices == null || !StringUtils.hasText(currentDevice)) {
            return false;
        }
        String current = currentDevice.trim();
        boolean systemKnown = current.contains(DEVICE_SYSTEM_SEPARATOR);
        for (String observed : observedDevices) {
            if (!StringUtils.hasText(observed)) {
                continue;
            }
            String value = observed.trim();
            if (value.equalsIgnoreCase(current)) {
                return true;
            }
            if (!systemKnown && value.toLowerCase(Locale.ROOT)
                    .startsWith((current + DEVICE_SYSTEM_SEPARATOR).toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeToken(Object rawValue) {
        if (rawValue == null) {
            return null;
        }
        String text = rawValue.toString().trim();
        if (!StringUtils.hasText(text)) {
            return null;
        }
        return text
                .replace('-', '_')
                .replace(' ', '_')
                .toUpperCase(Locale.ROOT);
    }

    private static boolean containsAny(String candidate, String... fragments) {
        if (!StringUtils.hasText(candidate) || fragments == null) {
            return false;
        }
        for (String fragment : fragments) {
            if (fragment != null && candidate.contains(fragment)) {
                return true;
            }
        }
        return false;
    }
}
