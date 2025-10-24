package io.contexa.contexaidentity.security.token.store;

import lombok.Getter;

import java.time.Instant;

@Getter
public class TokenInfo {

    public static final String REASON_LOGOUT = "LOGOUT";
    public static final String REASON_REVOKED = "REVOKED";
    public static final String REASON_EXPIRED = "EXPIRED";

    private String username;
    private Instant expiration;
    private String reason;

    public TokenInfo(String username, Instant expiration) {
        this(username, expiration, null);
    }

    public TokenInfo(String username, Instant expiration, String reason) {
        this.username = username;
        this.expiration = expiration;
        this.reason = reason;
    }
}
