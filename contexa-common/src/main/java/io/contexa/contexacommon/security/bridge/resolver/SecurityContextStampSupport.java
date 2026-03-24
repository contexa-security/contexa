package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.*;

final class SecurityContextStampSupport {

    private static final List<String> PRINCIPAL_ID_KEYS = List.of("principalId", "userId", "username", "loginId", "email", "sub", "subject", "id");

    private SecurityContextStampSupport() {
    }

    static String extractPrincipalId(Authentication authentication) {
        String fromDetails = BridgeObjectExtractor.extractString(authentication != null ? authentication.getDetails() : null, PRINCIPAL_ID_KEYS);
        if (fromDetails != null) {
            return fromDetails;
        }
        String fromPrincipal = BridgeObjectExtractor.extractString(authentication != null ? authentication.getPrincipal() : null, PRINCIPAL_ID_KEYS);
        if (fromPrincipal != null) {
            return fromPrincipal;
        }
        if (authentication == null) {
            return null;
        }
        return text(authentication.getName());
    }

    static String resolveSubjectIdFromRequestAttributes(HttpServletRequest request, BridgeProperties properties) {
        if (request != null && properties != null && properties.getAuthentication() != null && properties.getAuthentication().getRequestAttributes() != null) {
            String principalId = text(request.getAttribute(properties.getAuthentication().getRequestAttributes().getPrincipalId()));
            if (principalId != null) {
                return principalId;
            }
        }
        return resolveCurrentPrincipalId(request);
    }

    static String resolveSubjectIdFromHeaders(HttpServletRequest request, BridgeProperties properties) {
        if (request != null && properties != null && properties.getAuthentication() != null && properties.getAuthentication().getHeaders() != null) {
            String principalId = text(request.getHeader(properties.getAuthentication().getHeaders().getPrincipalId()));
            if (principalId != null) {
                return principalId;
            }
        }
        return resolveCurrentPrincipalId(request);
    }

    static String resolveCurrentPrincipalId(HttpServletRequest request) {
        if (request != null && request.getUserPrincipal() != null) {
            String principalId = text(request.getUserPrincipal().getName());
            if (principalId != null) {
                return principalId;
            }
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }
        return extractPrincipalId(authentication);
    }

    static String extractString(Authentication authentication, List<String> keys) {
        String fromDetails = BridgeObjectExtractor.extractString(authentication != null ? authentication.getDetails() : null, keys);
        if (fromDetails != null) {
            return fromDetails;
        }
        return BridgeObjectExtractor.extractString(authentication != null ? authentication.getPrincipal() : null, keys);
    }

    static String extractString(Object source, List<String> keys) {
        return BridgeObjectExtractor.extractString(source, keys);
    }

    static Boolean extractBoolean(Authentication authentication, List<String> keys) {
        Boolean fromDetails = BridgeObjectExtractor.extractBoolean(authentication != null ? authentication.getDetails() : null, keys);
        if (fromDetails != null) {
            return fromDetails;
        }
        return BridgeObjectExtractor.extractBoolean(authentication != null ? authentication.getPrincipal() : null, keys);
    }

    static Boolean extractBoolean(Object source, List<String> keys) {
        return BridgeObjectExtractor.extractBoolean(source, keys);
    }

    static Instant extractInstant(Authentication authentication, List<String> keys) {
        Instant fromDetails = BridgeObjectExtractor.extractInstant(authentication != null ? authentication.getDetails() : null, keys);
        if (fromDetails != null) {
            return fromDetails;
        }
        return BridgeObjectExtractor.extractInstant(authentication != null ? authentication.getPrincipal() : null, keys);
    }

    static Instant extractInstant(Object source, List<String> keys) {
        return BridgeObjectExtractor.extractInstant(source, keys);
    }

    static List<String> extractStringList(Authentication authentication, List<String> keys) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        values.addAll(BridgeObjectExtractor.extractStringSet(authentication != null ? authentication.getDetails() : null, keys));
        values.addAll(BridgeObjectExtractor.extractStringSet(authentication != null ? authentication.getPrincipal() : null, keys));
        return List.copyOf(values);
    }

    static Set<String> extractStringSet(Object source, List<String> keys) {
        return BridgeObjectExtractor.extractStringSet(source, keys);
    }

    static Map<String, Object> extractAttributes(Object source, List<String> keys) {
        return BridgeObjectExtractor.extractAttributes(source, keys);
    }

    static Map<String, Object> mergeAttributes(Object primary, Object secondary, List<String> keys) {
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.putAll(extractAttributes(primary, keys));
        attributes.putAll(extractAttributes(secondary, keys));
        return Map.copyOf(attributes);
    }

    static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }
}
