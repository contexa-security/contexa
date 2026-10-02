package io.contexa.demo.identity.dto;

import java.time.LocalDateTime;
import java.util.List;

public record IdentityAccount(
        Long sourceUserId,
        String username,
        String displayName,
        String passwordHash,
        boolean enabled,
        boolean accountLocked,
        boolean credentialsExpired,
        boolean externalAuthOnly,
        LocalDateTime lockExpiresAt,
        List<String> authorities
) {

}
