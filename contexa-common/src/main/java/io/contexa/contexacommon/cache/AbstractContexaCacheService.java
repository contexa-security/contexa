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
package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public abstract class AbstractContexaCacheService implements ContexaCacheService {

    protected final ContexaCacheProperties properties;
    protected final ObjectMapper objectMapper;
    protected final ConcurrentHashMap<String, Cache<String, String>> domainCaches = new ConcurrentHashMap<>();
    protected Cache<String, String> defaultLocalCache;

    protected AbstractContexaCacheService(ContexaCacheProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    protected Cache<String, String> getOrCreateDomainCache(String domain) {
        if (domain == null || domain.isEmpty()) {
            return defaultLocalCache;
        }

        return domainCaches.computeIfAbsent(domain, d -> {
            int ttl = getLocalTtl(d);
            return buildLocalCache(ttl);
        });
    }

    protected Cache<String, String> buildLocalCache(int ttlSeconds) {
        return Caffeine.newBuilder()
                .maximumSize(properties.getLocal().getMaxSize())
                .expireAfterWrite(ttlSeconds, TimeUnit.SECONDS)
                .recordStats()
                .build();
    }

    protected int getLocalTtl(String domain) {
        if (domain == null) {
            return properties.getLocal().getDefaultTtlSeconds();
        }

        ContexaCacheProperties.DomainConfig domains = properties.getDomains();
        return switch (domain.toLowerCase()) {
            case "users" -> domains.getUsers().getLocalTtlSeconds();
            case "roles" -> domains.getRoles().getLocalTtlSeconds();
            case "permissions" -> domains.getPermissions().getLocalTtlSeconds();
            case "groups" -> domains.getGroups().getLocalTtlSeconds();
            case "policies" -> domains.getPolicies().getLocalTtlSeconds();
            case "soar" -> domains.getSoar().getLocalTtlSeconds();
            default -> properties.getLocal().getDefaultTtlSeconds();
        };
    }
}
