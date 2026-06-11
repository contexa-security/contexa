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
package io.contexa.contexaidentity.security.token.dto;

import lombok.Builder;
import lombok.Getter;
import org.springframework.lang.Nullable;

import java.time.Instant;

@Getter
@Builder
public class TokenPair {

    private final String accessToken;

    @Nullable
    private final String refreshToken;

    private final Instant accessTokenExpiresAt;

    @Nullable
    private final Instant refreshTokenExpiresAt;

    @Nullable
    private final String scope;

    public boolean hasRefreshToken() {
        return refreshToken != null;
    }

    public boolean isAccessTokenExpired() {
        return accessTokenExpiresAt != null && Instant.now().isAfter(accessTokenExpiresAt);
    }

    public boolean isRefreshTokenExpired() {
        if (refreshTokenExpiresAt == null) {
            return true;
        }
        return Instant.now().isAfter(refreshTokenExpiresAt);
    }
}
