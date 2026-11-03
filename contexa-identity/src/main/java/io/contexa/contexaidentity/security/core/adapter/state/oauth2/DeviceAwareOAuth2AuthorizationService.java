/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

@Slf4j
public class DeviceAwareOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String FIND_IDS_BY_PRINCIPAL =
            "SELECT id FROM ctxa_oauth2_authorization WHERE principal_name = ? AND refresh_token_value IS NOT NULL";
    private static final String FIND_UNEXPIRED_IDS_BY_PRINCIPAL_AND_CLIENT =
            "SELECT id FROM ctxa_oauth2_authorization WHERE principal_name = ? AND registered_client_id = ?"
                    + " AND (access_token_expires_at > ? OR refresh_token_expires_at > ?)";

    private final OAuth2AuthorizationService delegate;
    private final JdbcTemplate jdbcTemplate;
    private final AuthContextProperties properties;
    private final TransactionTemplate transactionTemplate;
    /** Reads an authorization on one connection (RL-15); null where no transaction manager was given. */
    private final TransactionTemplate readTransactions;

    public DeviceAwareOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            JdbcTemplate jdbcTemplate,
            AuthContextProperties properties) {
        this(delegate, jdbcTemplate, properties, null);
    }

    public DeviceAwareOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            JdbcTemplate jdbcTemplate,
            AuthContextProperties properties,
            TransactionTemplate transactionTemplate) {

        Assert.notNull(delegate, "delegate cannot be null");
        Assert.notNull(jdbcTemplate, "jdbcTemplate cannot be null");
        Assert.notNull(properties, "properties cannot be null");
        this.delegate = delegate;
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
        this.transactionTemplate = transactionTemplate;
        this.readTransactions = readOnly(transactionTemplate);
    }

    private static TransactionTemplate readOnly(TransactionTemplate source) {
        if (source == null || source.getTransactionManager() == null) {
            return null;
        }
        TransactionTemplate reads = new TransactionTemplate(source.getTransactionManager(), source);
        reads.setReadOnly(true);
        return reads;
    }

    /**
     * docs/agent RL-15. The delegate maps the row of an authorization while its query still holds the connection, and the
     * row mapper looks the registered client up with a second query. Outside a transaction that is a second connection:
     * when as many callers as the pool has connections read at once, each holds one and waits for another, and the pool
     * of the engine stands still until the connection timeout ends the waits. Inside a transaction both queries use the
     * connection the transaction holds, so every read holds one connection whatever the number of callers.
     */
    private <T> T onOneConnection(Supplier<T> read) {
        return readTransactions == null ? read.get() : readTransactions.execute(status -> read.get());
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        // Only a newly created authorization is a new login. Updates of an existing one, such as a
        // refresh token rotation or a logout invalidation, must not count against the login limit.
        if (onOneConnection(() -> delegate.findById(authorization.getId())) == null) {
            enforceConcurrentLoginPolicy(authorization);
        }
        saveOnOneConnection(authorization);
    }

    /** The delegate reads the stored authorization before it writes, and that read has the same second query. */
    private void saveOnOneConnection(OAuth2Authorization authorization) {
        if (transactionTemplate == null) {
            delegate.save(authorization);
            return;
        }
        transactionTemplate.executeWithoutResult(status -> delegate.save(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return onOneConnection(() -> delegate.findById(id));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return onOneConnection(() -> delegate.findByToken(token, tokenType));
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

    /**
     * docs/agent A5-3: the principal's authorizations through the client whose access or refresh token still works,
     * with a refresh token or without one (client credentials and token exchange issue none), so that the tokens an
     * agent's client holds can be revoked. {@link #findActiveByPrincipalName} keeps answering the sign-ins only.
     *
     * @param registeredClientId the registered client's identifier (not its client id)
     */
    public List<OAuth2Authorization> findUsableByPrincipalNameAndClient(String principalName,
                                                                        String registeredClientId) {
        Assert.hasText(principalName, "principalName cannot be empty");
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Timestamp now = Timestamp.from(Instant.now());
        List<String> ids = jdbcTemplate.queryForList(FIND_UNEXPIRED_IDS_BY_PRINCIPAL_AND_CLIENT, String.class,
                principalName, registeredClientId, now, now);
        return ids.stream()
                .map(this::safeFindById)
                .filter(Objects::nonNull)
                .filter(authorization -> usable(authorization.getAccessToken())
                        || usable(authorization.getRefreshToken()))
                .toList();
    }

    private static boolean usable(OAuth2Authorization.Token<?> token) {
        return token != null && !token.isInvalidated() && !token.isExpired();
    }

    private OAuth2Authorization safeFindById(String id) {
        try {
            return onOneConnection(() -> delegate.findById(id));
        } catch (Exception e) {
            log.error("[OAuth2] Failed to deserialize authorization {}: {}", id, e.getMessage());
            cleanupCorruptedAuthorization(id);
            return null;
        }
    }

    private void cleanupCorruptedAuthorization(String id) {
        try {
            if (transactionTemplate != null) {
                transactionTemplate.executeWithoutResult(status ->
                        jdbcTemplate.update("DELETE FROM ctxa_oauth2_authorization WHERE id = ?", id));
            }
            else {
                jdbcTemplate.update("DELETE FROM ctxa_oauth2_authorization WHERE id = ?", id);
            }
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

        saveOnOneConnection(builder.build());
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
