package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Bridge between a legacy authentication system and Contexa's security context.
 * <p>
 * Implementations extract user identity from legacy mechanisms (session, JWT, cookie, etc.)
 * without modifying the legacy system. This is a <b>read-only</b> operation.
 * <p>
 * The extracted {@link BridgedUser} is converted into a Spring Security
 * {@code Authentication} object and placed in the {@code SecurityContext},
 * enabling Contexa's full Zero Trust pipeline to operate.
 *
 * <h3>Built-in implementations:</h3>
 * <ul>
 *   <li>{@code SessionAuthBridge} - extracts from HttpSession attribute</li>
 *   <li>{@code JwtAuthBridge} - extracts from Authorization Bearer token</li>
 *   <li>{@code CookieAuthBridge} - extracts from authentication cookie</li>
 * </ul>
 *
 * <h3>Custom implementation:</h3>
 * <pre>{@code
 * public class MyAuthBridge implements AuthBridge {
 *     public BridgedUser extractUser(HttpServletRequest request) {
 *         MyLegacyUser user = // extract from request
 *         return new BridgedUser(user.getId(), user.getName(),
 *             Set.of(user.getRole()), Map.of("dept", user.getDept()));
 *     }
 * }
 * }</pre>
 *
 * @see BridgedUser
 * @see io.contexa.contexacommon.annotation.EnableAISecurity
 */
public interface AuthBridge {

    /**
     * Extracts user identity from the legacy request.
     *
     * @param request the current HTTP request
     * @return bridged user information, or {@code null} if the user is not authenticated
     *         in the legacy system (e.g., session expired, no token provided)
     */
    BridgedUser extractUser(HttpServletRequest request);
}
