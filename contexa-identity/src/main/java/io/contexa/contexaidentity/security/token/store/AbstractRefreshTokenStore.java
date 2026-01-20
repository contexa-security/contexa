package io.contexa.contexaidentity.security.token.store;

import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Objects;


@Slf4j
@RequiredArgsConstructor
public abstract class AbstractRefreshTokenStore implements RefreshTokenStore {

    protected final JwtDecoder jwtDecoder;
    protected final AuthContextProperties props;

    
    protected String deviceKey(String username, String deviceId) {
        Objects.requireNonNull(username, "username cannot be null for deviceKey");
        Objects.requireNonNull(deviceId, "deviceId cannot be null for deviceKey");
        return username + ":" + deviceId;
    }

    @Override
    public void save(String refreshToken, String username) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");
        Objects.requireNonNull(username, "username cannot be null");

        
        if (refreshToken.trim().isEmpty()) {
            log.warn("Empty refreshToken provided, cannot save. User: {}", username);
            return;
        }

        
        String[] parts = refreshToken.split("\\.");
        if (parts.length != 3) {
            log.warn("Malformed JWT token (expected 3 parts separated by dots, got {}). User: {}",
                     parts.length, username);
            return;
        }

        try {
            
            Jwt jwt = jwtDecoder.decode(refreshToken);

            String deviceId = jwt.getClaim("deviceId");
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot save. User: {}", username);
                return;
            }

            Instant expiry = jwt.getExpiresAt();
            if (expiry == null) {
                log.warn("Expiration is null in refreshToken, cannot save. User: {}, deviceId: {}", username, deviceId);
                return;
            }

            if (Instant.now().isAfter(expiry)) {
                log.warn("Token already expired, not saving. User: {}, deviceId: {}", username, deviceId);
                return;
            }

            
            handleConcurrentLoginPolicy(username, deviceId);

            
            doSaveToken(username, deviceId, refreshToken, expiry);

            log.debug("Saved refresh token for user: {}, deviceId: {}", username, deviceId);

        } catch (JwtException e) {
            log.warn("JWT decoding failed - refreshToken save failed. User: {}. Error: {}", username, e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during refreshToken save. User: {}. Error: {}", username, e.getMessage(), e);
        }
    }

    @Override
    public String getUsername(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");

        try {
            if (isBlacklisted(refreshToken)) {
                log.warn("Attempt to use blacklisted refresh token (for getUsername): {}", refreshToken);
                return null;
            }

            
            Jwt jwt = jwtDecoder.decode(refreshToken);

            String subject = jwt.getSubject();
            String deviceId = jwt.getClaim("deviceId");
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot get username. Subject: {}", subject);
                return null;
            }

            TokenInfo tokenInfo = doGetTokenInfo(subject, deviceId);
            if (tokenInfo == null) {
                log.debug("No refresh token found in store for user: {}, deviceId: {}", subject, deviceId);
                return null;
            }

            if (Instant.now().isAfter(tokenInfo.getExpiration())) {
                log.info("Refresh token expired for user: {}, deviceId: {}, removing from store.", subject, deviceId);
                handleExpiredToken(subject, deviceId, refreshToken);
                return null;
            }

            return tokenInfo.getUsername();

        } catch (JwtException e) {
            log.warn("JWT decoding failed - getUsername failed. Error: {}", e.getMessage(), e);
            return null;
        } catch (Exception e) {
            log.error("Unexpected error during getUsername. Error: {}", e.getMessage(), e);
            return null;
        }
    }

    @Override
    public void remove(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken cannot be null");

        try {
            
            Jwt jwt = jwtDecoder.decode(refreshToken);

            String subject = jwt.getSubject();
            String deviceId = jwt.getClaim("deviceId");
            if (deviceId == null) {
                log.warn("deviceId is null in refreshToken, cannot remove. Subject: {}", subject);
                return;
            }

            doRemoveToken(subject, deviceId);
            log.debug("Removed refresh token from store for user: {}, deviceId: {}", subject, deviceId);

        } catch (JwtException e) {
            log.warn("JWT decoding failed - refreshToken removal failed. Error: {}", e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during refreshToken removal. Error: {}", e.getMessage(), e);
        }
    }

    @Override
    public void blacklist(String token, String username, String reason) {
        Objects.requireNonNull(token, "token cannot be null");
        Objects.requireNonNull(username, "username cannot be null for blacklist");

        try {
            
            Jwt jwt = jwtDecoder.decode(token);

            Instant expiration = jwt.getExpiresAt();
            if (expiration == null) {
                log.warn("Expiration is null in token, using fallback. User: {}", username);
                expiration = Instant.now().plusMillis(props.getRefreshTokenValidity());
            }

            doBlacklistToken(token, jwt.getSubject(), expiration, reason);
            log.info("Token blacklisted: user={}, reason={}", jwt.getSubject(), reason);
        } catch (JwtException e) {
            log.warn("JWT decoding failed for token blacklist. User: {}. Reason: {}. Using fallback.", username, reason, e);
            
            Instant fallbackExpiry = Instant.now().plusMillis(props.getRefreshTokenValidity());
            doBlacklistToken(token, username, fallbackExpiry, reason);
        } catch (Exception e) {
            log.error("Unexpected error during token blacklist. Token: {}. User: {}. Reason: {}", token, username, reason, e);
        }
    }

    @Override
    public void blacklistDevice(String username, String deviceId, String reason) {
        Objects.requireNonNull(username, "username cannot be null for device blacklist");
        Objects.requireNonNull(deviceId, "deviceId cannot be null for device blacklist");

        doBlacklistDevice(username, deviceId, reason);
        log.info("Device blacklisted: user={}, deviceId={}, reason={}", username, deviceId, reason);
    }

    
    private void handleConcurrentLoginPolicy(String username, String currentDeviceId) {
        if (!props.isAllowMultipleLogins()) {
            
            evictAllUserDevices(username, "Single login enforced");
        } else {
            
            enforceMaxConcurrentLogins(username, currentDeviceId);
        }
    }

    
    private void handleExpiredToken(String username, String deviceId, String token) {
        doRemoveToken(username, deviceId);
        blacklist(token, username, TokenInfo.REASON_EXPIRED);
    }

    
    private void evictAllUserDevices(String username, String reason) {
        for (String deviceId : doGetUserDevices(username)) {
            evictAndBlacklist(username, deviceId, reason);
        }
    }

    
    private void enforceMaxConcurrentLogins(String username, String currentDeviceId) {
        int currentCount = doGetUserDeviceCount(username);

        if (currentCount >= props.getMaxConcurrentLogins()) {
            String oldestDeviceId = doGetOldestDevice(username);
            if (oldestDeviceId != null && !oldestDeviceId.equals(currentDeviceId)) {
                evictAndBlacklist(username, oldestDeviceId, "Max concurrent login exceeded");
            }
        }
    }

    
    private void evictAndBlacklist(String username, String deviceId, String reason) {
        doRemoveToken(username, deviceId);
        blacklistDevice(username, deviceId, reason);
        log.info("Evicted and blacklisted deviceId: {} for user: {} due to: {}", deviceId, username, reason);
    }

    

    
    protected abstract void doSaveToken(String username, String deviceId, String token, Instant expiration);

    
    protected abstract TokenInfo doGetTokenInfo(String username, String deviceId);

    
    protected abstract void doRemoveToken(String username, String deviceId);

    
    protected abstract void doBlacklistToken(String token, String username, Instant expiration, String reason);

    
    protected abstract void doBlacklistDevice(String username, String deviceId, String reason);

    
    protected abstract Iterable<String> doGetUserDevices(String username);

    
    protected abstract int doGetUserDeviceCount(String username);

    
    protected abstract String doGetOldestDevice(String username);
}