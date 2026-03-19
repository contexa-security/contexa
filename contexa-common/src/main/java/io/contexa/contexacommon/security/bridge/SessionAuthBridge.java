package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Bridges legacy session-based authentication into Contexa.
 * <p>
 * Reads the user object from {@link HttpSession} using the configured attribute name,
 * then extracts username, roles, and other attributes via reflection or known interfaces.
 * <p>
 * Supports diverse legacy session objects:
 * <ul>
 *   <li><b>String</b> - treated as username directly</li>
 *   <li><b>Map</b> - looks for "username"/"userId"/"id" and "roles"/"authorities" keys</li>
 *   <li><b>Any object</b> - uses reflection to find getter methods</li>
 * </ul>
 */
@Slf4j
public class SessionAuthBridge implements AuthBridge {

    private final String sessionAttribute;

    public SessionAuthBridge(String sessionAttribute) {
        this.sessionAttribute = sessionAttribute;
    }

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }

        Object sessionUser = session.getAttribute(sessionAttribute);
        if (sessionUser == null) {
            return null;
        }

        return convertToBridgedUser(sessionUser);
    }

    private BridgedUser convertToBridgedUser(Object sessionUser) {
        if (sessionUser instanceof String username) {
            return new BridgedUser(username);
        }

        if (sessionUser instanceof Map<?, ?> map) {
            return extractFromMap(map);
        }

        return extractFromObject(sessionUser);
    }

    @SuppressWarnings("unchecked")
    private BridgedUser extractFromMap(Map<?, ?> map) {
        String username = extractStringFromMap(map, "username", "userId", "id", "loginId", "email");
        if (username == null) {
            log.error("[AuthBridge] Cannot extract username from session Map. Available keys: {}", map.keySet());
            return null;
        }

        String displayName = extractStringFromMap(map, "displayName", "name", "fullName", "userName");
        Set<String> roles = extractRolesFromMap(map);
        Map<String, Object> attributes = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() instanceof String key) {
                attributes.put(key, entry.getValue());
            }
        }

        return new BridgedUser(
                username,
                displayName != null ? displayName : username,
                roles,
                attributes
        );
    }

    private BridgedUser extractFromObject(Object obj) {
        Class<?> clazz = obj.getClass();
        String username = invokeGetter(obj, clazz, "getUserId", "getUsername", "getId", "getLoginId", "getEmail");
        if (username == null) {
            log.error("[AuthBridge] Cannot extract username from session object type: {}", clazz.getName());
            return null;
        }

        String displayName = invokeGetter(obj, clazz, "getDisplayName", "getName", "getFullName", "getUserName");
        Set<String> roles = extractRolesFromObject(obj, clazz);
        Map<String, Object> attributes = extractAttributesFromObject(obj, clazz);

        return new BridgedUser(
                username,
                displayName != null ? displayName : username,
                roles,
                attributes
        );
    }

    private String extractStringFromMap(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractRolesFromMap(Map<?, ?> map) {
        Set<String> roles = new LinkedHashSet<>();
        Object rolesObj = map.get("roles");
        if (rolesObj == null) rolesObj = map.get("authorities");
        if (rolesObj == null) rolesObj = map.get("role");

        if (rolesObj instanceof Collection<?> collection) {
            for (Object item : collection) {
                roles.add(item.toString());
            }
        } else if (rolesObj instanceof String roleStr) {
            for (String role : roleStr.split(",")) {
                String trimmed = role.trim();
                if (!trimmed.isEmpty()) roles.add(trimmed);
            }
        }
        return roles;
    }

    private String invokeGetter(Object obj, Class<?> clazz, String... methodNames) {
        for (String methodName : methodNames) {
            try {
                Method method = clazz.getMethod(methodName);
                Object result = method.invoke(obj);
                if (result != null) {
                    return result.toString();
                }
            } catch (NoSuchMethodException ignored) {
            } catch (Exception e) {
                log.error("[AuthBridge] Failed to invoke {}.{}", clazz.getSimpleName(), methodName, e);
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractRolesFromObject(Object obj, Class<?> clazz) {
        Set<String> roles = new LinkedHashSet<>();
        for (String methodName : new String[]{"getRoles", "getAuthorities", "getRole"}) {
            try {
                Method method = clazz.getMethod(methodName);
                Object result = method.invoke(obj);
                if (result instanceof Collection<?> collection) {
                    for (Object item : collection) {
                        roles.add(item.toString());
                    }
                    return roles;
                } else if (result instanceof String roleStr) {
                    for (String role : roleStr.split(",")) {
                        String trimmed = role.trim();
                        if (!trimmed.isEmpty()) roles.add(trimmed);
                    }
                    return roles;
                }
            } catch (NoSuchMethodException ignored) {
            } catch (Exception e) {
                log.error("[AuthBridge] Failed to extract roles via {}", methodName, e);
            }
        }
        return roles;
    }

    private Map<String, Object> extractAttributesFromObject(Object obj, Class<?> clazz) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        for (String methodName : new String[]{"getDepartment", "getLoginIp", "getAuthMethod", "getLoginTime"}) {
            try {
                Method method = clazz.getMethod(methodName);
                Object result = method.invoke(obj);
                if (result != null) {
                    String key = methodName.substring(3, 4).toLowerCase() + methodName.substring(4);
                    attributes.put(key, result);
                }
            } catch (NoSuchMethodException ignored) {
            } catch (Exception ignored) {
            }
        }
        return attributes;
    }
}
