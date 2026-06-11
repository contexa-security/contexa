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
package io.contexa.contexacore.autonomous.saas.security;

import io.contexa.contexacore.properties.SaasForwardingProperties;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class TenantScopedPseudonymizationService {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private final SaasForwardingProperties properties;

    public TenantScopedPseudonymizationService(SaasForwardingProperties properties) {
        this.properties = properties;
    }

    public String hash(String tenantScope, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return hmac(properties.getPseudonymizationSecret(), tenantScope + ":" + value);
        }
        catch (Exception e) {
            throw new IllegalStateException("Failed to pseudonymize XAI forwarding field", e);
        }
    }

    public String hashGlobal(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return hmac(properties.getGlobalCorrelationSecret(), value);
        }
        catch (Exception e) {
            throw new IllegalStateException("Failed to create global XAI correlation key", e);
        }
    }

    private String hmac(String secret, String value) throws Exception {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
        mac.init(keySpec);
        byte[] raw = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(raw);
    }
}
