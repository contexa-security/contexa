package io.contexa.contexaidentity.security.token.management;

import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;

import java.time.Instant;
import java.util.List;
import java.util.Optional;


public interface EnhancedRefreshTokenStore extends RefreshTokenStore {

    
    void rotate(String oldToken, String newToken, String username, String deviceId, ClientInfo clientInfo);

    
    void recordUsage(String token, TokenAction action, ClientInfo clientInfo);

    
    boolean isTokenReused(String token);

    
    AnomalyDetectionResult detectAnomaly(String username, String deviceId, ClientInfo clientInfo);

    
    void revokeAllUserTokens(String username, String reason);

    
    void revokeDeviceTokens(String username, String deviceId, String reason);

    
    List<TokenUsageHistory> getTokenHistory(String username, int limit);

    
    List<ActiveSession> getActiveSessions(String username);

    
    Optional<TokenMetadata> getTokenMetadata(String token);

    

    
    record ClientInfo(
            String ipAddress,
            String userAgent,
            String deviceFingerprint,
            String location,
            Instant timestamp
    ) {}

    
    enum TokenAction {
        CREATED,      
        USED,         
        ROTATED,      
        REUSED,       
        BLACKLISTED,  
        EXPIRED,      
        REVOKED       
    }

    
    record AnomalyDetectionResult(
            boolean isAnomalous,
            AnomalyType type,
            String description,
            double riskScore
    ) {}

    
    enum AnomalyType {
        NONE,                    
        RAPID_REFRESH,          
        GEOGRAPHIC_ANOMALY,     
        DEVICE_MISMATCH,        
        REUSED_TOKEN,           
        SUSPICIOUS_PATTERN      
    }

    
    record TokenUsageHistory(
            String token,
            TokenAction action,
            ClientInfo clientInfo,
            Instant timestamp,
            boolean successful
    ) {}

    
    record ActiveSession(
            String deviceId,
            String deviceName,
            String lastIpAddress,
            String location,
            Instant lastActivity,
            Instant createdAt,
            boolean current
    ) {}

    
    record TokenMetadata(
            String username,
            String deviceId,
            Instant issuedAt,
            Instant expiresAt,
            Instant lastUsedAt,
            int usageCount,
            String tokenChainId,  
            boolean isActive
    ) {}
}