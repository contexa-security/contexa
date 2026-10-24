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
package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The keys decision records and sealed evidence are signed with (docs/agent A5-6).
 */
@Data
@ConfigurationProperties(prefix = "contexa.security.evidence.signing")
public class EvidenceSigningProperties {

    /**
     * The key new signatures are made with. It may be left out when one key is configured. Without any key an
     * ephemeral key is used and its signatures read as not verifiable after a restart.
     */
    private String activeKeyId;

    /**
     * The signing keys, key ID to a Base64 secret of at least 32 bytes. Keep a retired key listed so that the records
     * it signed still verify.
     */
    private Map<String, String> keys = new LinkedHashMap<>();
}
