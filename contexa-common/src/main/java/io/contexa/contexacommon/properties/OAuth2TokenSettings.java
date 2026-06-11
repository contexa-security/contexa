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

import lombok.Data;

@Data
public class OAuth2TokenSettings {

    private String clientId = "default-client";
    private String clientSecret = "173f8245-5f7d-4623-a612-aa0c68f6da4a";
    private String issuerUri = "http://localhost:9000";
    private String tokenEndpoint = "/oauth2/token";
    private String scope = "read";
    private String redirectUri = "http://localhost:8080";
    private String authorizedUri;

    private String jwkKeyStorePath;
    private String jwkKeyStorePassword;
    private String jwkKeyAlias;
    private String jwkKeyPassword;
}
