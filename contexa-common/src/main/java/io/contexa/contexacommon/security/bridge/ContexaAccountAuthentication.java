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
package io.contexa.contexacommon.security.bridge;

import io.contexa.contexacommon.operating.OwnershipBehaviour;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.ClassUtils;

import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * Whether an authentication is one of Contexa's own accounts, told from the authentication alone. Where Contexa owns the
 * sign-in, Contexa's user store signs its accounts in with {@link UnifiedCustomUserDetails}, and an access token naming a
 * user (not a client's own token) is accepted only for an account the user store holds, which is Contexa's store when no
 * store of the application's signs the users in. Such a user is the account itself: it has no copy, and nothing needs to
 * be read to know who it is.
 */
public final class ContexaAccountAuthentication {

    private static final boolean JOSE_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.jwt.Jwt", ContexaAccountAuthentication.class.getClassLoader());

    private ContexaAccountAuthentication() {
    }

    /**
     * The name of the Contexa account the authentication is of, or {@code null} when it is not one, as far as the
     * authentication tells: an application's user, a client's own token, or a token while the application's own store
     * signs the users in.
     *
     * @param contexaAccountsSignIn whether Contexa's user store is the one that signs the users in
     */
    @Nullable
    public static String accountName(@Nullable Authentication authentication, @Nullable BridgeProperties properties,
                                     BooleanSupplier contexaAccountsSignIn) {
        if (authentication == null || properties == null
                || properties.ownershipBehaviour() != OwnershipBehaviour.CONTEXA_OWNED
                || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UnifiedCustomUserDetails userDetails) {
            return text(userDetails.getUsername());
        }
        if (!JOSE_PRESENT || contexaAccountsSignIn == null) {
            return null;
        }
        Map<String, Object> claims = JoseTypes.claims(principal);
        if (claims == null || AgentTokenClaims.isClientOwnToken(claims, tokenSettings(properties))
                || !contexaAccountsSignIn.getAsBoolean()) {
            return null;
        }
        return text(claims.get("sub"));
    }

    private static BridgeProperties.Delegation.Token tokenSettings(BridgeProperties properties) {
        return properties.getDelegation() != null && properties.getDelegation().getToken() != null
                ? properties.getDelegation().getToken()
                : new BridgeProperties.Delegation.Token();
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    /** Loaded only when the JOSE module is on the class path. */
    private static final class JoseTypes {

        private JoseTypes() {
        }

        @Nullable
        static Map<String, Object> claims(@Nullable Object principal) {
            return principal instanceof Jwt jwt ? jwt.getClaims() : null;
        }
    }
}
