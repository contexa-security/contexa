package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

@Slf4j
public class DeviceAwareOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String FIND_IDS_BY_PRINCIPAL =
            "SELECT id FROM oauth2_authorization WHERE principal_name = ? AND refresh_token_value IS NOT NULL";

    private final OAuth2AuthorizationService delegate;
    private final JdbcTemplate jdbcTemplate;
    private final AuthContextProperties properties;

    public DeviceAwareOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            JdbcTemplate jdbcTemplate,
            AuthContextProperties properties) {

        Assert.notNull(delegate, "delegate cannot be null");
        Assert.notNull(jdbcTemplate, "jdbcTemplate cannot be null");
        Assert.notNull(properties, "properties cannot be null");
        this.delegate = delegate;
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        enforceConcurrentLoginPolicy(authorization);
        delegate.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }

    public List<OAuth2Authorization> findActiveByPrincipalName(String principalName) {
        Assert.hasText(principalName, "principalName cannot be empty");

        List<String> ids = jdbcTemplate.queryForList(FIND_IDS_BY_PRINCIPAL, String.class, principalName);

        return ids.stream()
                .map(this::safeFindById)
                .filter(Objects::nonNull)
                .filter(this::isActiveAuthorization)
                .toList();
    }

    private OAuth2Authorization safeFindById(String id) {
        try {
            return delegate.findById(id);
        } catch (Exception e) {
            log.error("[OAuth2] Failed to deserialize authorization {}: {}", id, e.getMessage());
            cleanupCorruptedAuthorization(id);
            return null;
        }
    }

    private void cleanupCorruptedAuthorization(String id) {
        try {
            jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE id = ?", id);
        } catch (Exception e) {
            log.error("[OAuth2] Failed to cleanup corrupted authorization {}: {}", id, e.getMessage());
        }
    }

    public void invalidateAuthorization(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken != null && !refreshToken.isInvalidated()) {
            builder.token(refreshToken.getToken(), metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken != null && !accessToken.isInvalidated()) {
            builder.token(accessToken.getToken(), metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        }

        delegate.save(builder.build());
    }

    public void invalidateAllByPrincipalName(String principalName) {
        Assert.hasText(principalName, "principalName cannot be empty");

        List<OAuth2Authorization> activeAuthorizations = findActiveByPrincipalName(principalName);
        activeAuthorizations.forEach(this::invalidateAuthorization);
    }

    private void enforceConcurrentLoginPolicy(OAuth2Authorization authorization) {
        if (authorization.getRefreshToken() == null) {
            return;
        }

        String principalName = authorization.getPrincipalName();
        if (principalName == null) {
            return;
        }

        List<OAuth2Authorization> existing = findActiveByPrincipalName(principalName);

        if (!properties.isAllowMultipleLogins()) {
            existing.forEach(this::invalidateAuthorization);
        } else {
            int max = properties.getMaxConcurrentLogins();
            if (existing.size() >= max) {
                int countToRemove = existing.size() - max + 1;
                existing.stream()
                        .sorted(Comparator.comparing(this::getRefreshTokenIssuedAt))
                        .limit(countToRemove)
                        .forEach(this::invalidateAuthorization);
            }
        }
    }

    private boolean isActiveAuthorization(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        return refreshToken != null
                && !refreshToken.isInvalidated()
                && !refreshToken.isExpired();
    }

    private Instant getRefreshTokenIssuedAt(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken != null && refreshToken.getToken().getIssuedAt() != null) {
            return refreshToken.getToken().getIssuedAt();
        }
        return Instant.MIN;
    }
}
