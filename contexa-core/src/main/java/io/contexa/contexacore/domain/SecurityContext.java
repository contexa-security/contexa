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
package io.contexa.contexacore.domain;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Getter
@Setter
public class SecurityContext {
    private final Map<String, Object> securityAttributes;
    private String currentUser;
    private String sessionId;
    private String sourceIp;
    private boolean authenticated;
    
    public SecurityContext() {
        this.securityAttributes = new ConcurrentHashMap<>();
        this.authenticated = false;
    }
    
    public SecurityContext(String currentUser, String sessionId) {
        this();
        this.currentUser = currentUser;
        this.sessionId = sessionId;
        this.authenticated = true;
    }
    
    public void addSecurityAttribute(String key, Object value) {
        this.securityAttributes.put(key, value);
    }
    public Object getSecurityAttribute(String key) {
        return this.securityAttributes.get(key);
    }
    public Map<String, Object> getSecurityAttributes() { return Map.copyOf(securityAttributes); }

    @Override
    public String toString() {
        return String.format("SecurityContext{user='%s', session='%s', authenticated=%s}", 
                currentUser, sessionId, authenticated);
    }
} 