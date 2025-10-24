package io.contexa.contexaidentity.security.token.store;

public interface RefreshTokenStore{
    void save(String token, String username);
    void remove(String token);
    String getUsername(String refreshToken);
    void blacklist(String token, String username, String reason);
    void blacklistDevice(String token, String username, String reason);
    boolean isBlacklisted(String token);
}
