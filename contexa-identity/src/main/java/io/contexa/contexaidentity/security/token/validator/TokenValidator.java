package io.contexa.contexaidentity.security.token.validator;

import org.springframework.security.core.Authentication;


public interface TokenValidator {

    
    boolean validateAccessToken(String token);

    
    boolean validateRefreshToken(String token);

    
    void invalidateRefreshToken(String refreshToken);

    
    Authentication getAuthentication(String token);

    
    default boolean shouldRotateRefreshToken(String refreshToken) {
        return false;
    }
}
