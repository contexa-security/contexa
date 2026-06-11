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

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

@Slf4j
public final class OAuth2CsrfConfigurer extends AbstractHttpConfigurer<OAuth2CsrfConfigurer, HttpSecurity> {

    private final boolean oauth2Csrf;

    public OAuth2CsrfConfigurer(boolean oauth2Csrf) {
        this.oauth2Csrf = oauth2Csrf;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        if (!oauth2Csrf) {
            http.csrf(AbstractHttpConfigurer::disable);
        }
        log.error("OAuth2CsrfConfigurer: CSRF {}", oauth2Csrf ? "enabled" : "disabled for OAuth2 mode");
    }
}
