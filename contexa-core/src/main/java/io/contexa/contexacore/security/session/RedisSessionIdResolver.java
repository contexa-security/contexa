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
package io.contexa.contexacore.security.session;

import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.concurrent.TimeUnit;

/**
 * Redis-backed implementation of SessionIdResolver for distributed mode.
 * Validates session existence and TTL against Redis store.
 */
@Slf4j
public class RedisSessionIdResolver extends AbstractSessionIdResolver {

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisSessionIdResolver(RedisTemplate<String, Object> redisTemplate,
                                  SecuritySessionProperties securitySessionProperties) {
        super(securitySessionProperties);
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected boolean validateSession(String sessionId) {
        String redisKey = "spring:session:sessions:" + sessionId;
        try {
            Boolean exists = redisTemplate.hasKey(redisKey);

            if (Boolean.FALSE.equals(exists)) {
                return false;
            }

            Long ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
            return ttl == null || ttl > 0;
        } catch (RuntimeException unreadable) {
            // D-19 (PR-84): what cannot be read says nothing against the session; the in-memory resolver takes it as valid.
            if (!StoreFailures.isReportedOutage(unreadable)) {
                log.error("Failed to validate a session in Redis; it is taken as valid: {}", sessionId, unreadable);
            }
            return true;
        }
    }

    @Override
    protected String[] getSessionAttributeNames() {
        return SESSION_ATTRIBUTE_NAMES.clone();
    }
}
