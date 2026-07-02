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
package io.contexa.contexacommon.properties;

import io.contexa.contexacommon.enums.*;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Data
@ConfigurationProperties(prefix = "contexa.auth")
public class AuthContextProperties {

    private StateType stateType = StateType.OAUTH2;

    private TokenTransportType tokenTransportType = TokenTransportType.HEADER;

    private TokenIssuer tokenIssuer = TokenIssuer.INTERNAL;

    private FactorSelectionType factorSelectionType = FactorSelectionType.SELECT;

    @NestedConfigurationProperty
    private AuthUrlConfig urls = new AuthUrlConfig();

    @NestedConfigurationProperty
    private MfaSettings mfa = new MfaSettings();

    @NestedConfigurationProperty
    private OttSettings ott = new OttSettings();

    @NestedConfigurationProperty
    private JwtsTokenSettings internal = new JwtsTokenSettings();

    @NestedConfigurationProperty
    private OAuth2TokenSettings oauth2 = new OAuth2TokenSettings();

    private long accessTokenValidity = 3600000;       
    private long refreshTokenValidity = 604800000;    
    private long refreshRotateThreshold = 43200000; 

    private boolean enableRefreshToken = true;
    private boolean allowMultipleLogins = false;
    private int maxConcurrentLogins = 3;
    private boolean cookieSecure = true;

    private String tokenPersistence = "memory";

    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";
    private boolean oauth2Csrf = false;

    @Data
    public static class OttSettings {
        private boolean failOnEmailError = true;
    }

}
