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
package io.contexa.autoconfigure.ai;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.lang.reflect.Field;

public class BridgeOAuth2ResourceServerFallbackConfigurer extends AbstractHttpConfigurer<BridgeOAuth2ResourceServerFallbackConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        OAuth2ResourceServerConfigurer<HttpSecurity> configurer = http.getConfigurer(OAuth2ResourceServerConfigurer.class);
        if (configurer == null) {
            return;
        }
        if (hasOpaqueTokenConfigurer(configurer) || hasJwtConfigurer(configurer)) {
            return;
        }
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        if (applicationContext == null) {
            return;
        }
        if (applicationContext.getBeanNamesForType(JwtDecoder.class).length == 0) {
            return;
        }
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
    }

    private boolean hasJwtConfigurer(OAuth2ResourceServerConfigurer<?> configurer) {
        return readField(configurer, "jwtConfigurer") != null;
    }

    private boolean hasOpaqueTokenConfigurer(OAuth2ResourceServerConfigurer<?> configurer) {
        return readField(configurer, "opaqueTokenConfigurer") != null;
    }

    private Object readField(OAuth2ResourceServerConfigurer<?> configurer, String fieldName) {
        try {
            Field field = OAuth2ResourceServerConfigurer.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(configurer);
        } catch (Exception ex) {
            return null;
        }
    }
}
