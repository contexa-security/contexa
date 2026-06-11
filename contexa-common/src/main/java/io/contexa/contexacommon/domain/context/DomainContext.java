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
package io.contexa.contexacommon.domain.context;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;


@Getter
@Setter
public abstract class DomainContext {
    
    private final String contextId;
    private final LocalDateTime createdAt;
    private final Map<String, Object> metadata;
    private String userId;
    private String sessionId;
    private String organizationId;

    protected DomainContext() {
        this.contextId = UUID.randomUUID().toString();
        this.createdAt = LocalDateTime.now();
        this.metadata = new ConcurrentHashMap<>();
    }
    
    protected DomainContext(String userId, String sessionId) {
        this();
        this.userId = userId;
        this.sessionId = sessionId;
    }
    

    public abstract String getDomainType();

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }

    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    public Map<String, Object> getAllMetadata() {
        return Map.copyOf(metadata);
    }

    @Override
    public String toString() {
        return String.format("%s{id='%s', domain='%s'}",
                getClass().getSimpleName(), contextId, getDomainType());
    }
} 