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
package io.contexa.contexacore.security.async;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.List;

/**
 * Z-16 (F7): read back through its builder, so the Redis provider reads what it wrote (without a creator Jackson could
 * not, and every Redis read came back empty where the in-memory provider answered).
 */
@Data
@Builder
@Jacksonized
public class AsyncAuthenticationData implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String userId;
    private String sessionId;
    private String principalType;
    private List<String> authorities;
    private Instant createdAt;
    private Instant expiresAt;

    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    @JsonIgnore
    public boolean isValid() {
        return userId != null && !userId.isEmpty() && !isExpired();
    }
}
