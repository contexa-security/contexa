package io.contexa.test;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.RiskLevel;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shared test data factory for security-related test fixtures.
 */
public final class SecurityTestFixtures {

    private SecurityTestFixtures() {
    }

    // -- UserDto --

    public static UserDto defaultUser() {
        return UserDto.builder()
                .id(1L)
                .username("testuser@contexa.io")
                .password("encoded_password")
                .name("Test User")
                .mfaEnabled(false)
                .createdAt(LocalDateTime.of(2025, 1, 1, 0, 0))
                .updatedAt(LocalDateTime.of(2025, 1, 1, 0, 0))
                .roles(List.of("ROLE_USER"))
                .permissions(List.of("read", "write"))
                .build();
    }

    public static UserDto adminUser() {
        return UserDto.builder()
                .id(2L)
                .username("admin@contexa.io")
                .password("encoded_password")
                .name("Admin User")
                .mfaEnabled(true)
                .createdAt(LocalDateTime.of(2025, 1, 1, 0, 0))
                .updatedAt(LocalDateTime.of(2025, 1, 1, 0, 0))
                .roles(List.of("ROLE_ADMIN", "ROLE_USER"))
                .permissions(List.of("read", "write", "delete", "admin"))
                .build();
    }

    // -- UnifiedCustomUserDetails --

    public static UnifiedCustomUserDetails defaultUserDetails() {
        return new UnifiedCustomUserDetails(defaultUser(), authorities("ROLE_USER"));
    }

    public static UnifiedCustomUserDetails adminUserDetails() {
        return new UnifiedCustomUserDetails(adminUser(), authorities("ROLE_ADMIN", "ROLE_USER"));
    }

    // -- GrantedAuthority --

    public static Set<GrantedAuthority> authorities(String... roles) {
        return Set.of(roles).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    // -- HCADContext --

    public static HCADContext defaultHcadContext() {
        return HCADContext.builder()
                .userId("testuser@contexa.io")
                .sessionId("session-001")
                .username("testuser@contexa.io")
                .requestPath("/api/resource")
                .httpMethod("GET")
                .remoteIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .timestamp(Instant.parse("2025-06-01T12:00:00Z"))
                .isNewSession(false)
                .isNewDevice(false)
                .isNewUser(false)
                .riskScore(10)
                .anomalyScore(0.0)
                .build();
    }

    public static HCADContext suspiciousHcadContext() {
        return HCADContext.builder()
                .userId("attacker@external.com")
                .sessionId("session-999")
                .username("attacker@external.com")
                .requestPath("/api/admin/users")
                .httpMethod("DELETE")
                .remoteIp("10.0.0.1")
                .userAgent("curl/7.68.0")
                .timestamp(Instant.parse("2025-06-01T03:00:00Z"))
                .isNewSession(true)
                .isNewDevice(true)
                .isNewUser(true)
                .riskScore(90)
                .anomalyScore(0.85)
                .failedLoginAttempts(5)
                .build();
    }

    // -- Constants --

    public static final String TEST_SESSION_ID = "test-session-001";
    public static final String TEST_USER_ID = "testuser@contexa.io";
    public static final String TEST_IP = "192.168.1.100";
    public static final String TEST_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
}
