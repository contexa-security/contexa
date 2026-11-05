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
package io.contexa.contexacore.verification.evidence;

import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HMAC-SHA256 signatures over record hashes (docs/agent A5-6). The keys come from
 * {@code contexa.security.evidence.signing.keys} (key ID to a Base64 secret of at least 32 bytes) and new signatures
 * use {@code active-key-id}; older keys stay listed so the records they signed still verify. Without a configured key
 * an ephemeral key is generated and reported: records then verify only until the application restarts, after which
 * they read as not verifiable, never as changed.
 */
@Slf4j
public final class HmacEvidenceSigner implements EvidenceSigner {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int MIN_KEY_BYTES = 32;

    private final Map<String, byte[]> keys;
    private final String activeKeyId;
    private final boolean configured;

    public HmacEvidenceSigner(Map<String, byte[]> keys, String activeKeyId) {
        this(keys, activeKeyId, true);
    }

    private HmacEvidenceSigner(Map<String, byte[]> keys, String activeKeyId, boolean configured) {
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("An evidence signer needs at least one key");
        }
        Map<String, byte[]> copy = new LinkedHashMap<>();
        keys.forEach((id, secret) -> {
            if (!StringUtils.hasText(id) || secret == null || secret.length < MIN_KEY_BYTES) {
                throw new IllegalArgumentException("Evidence signing key " + id + " must be at least "
                        + MIN_KEY_BYTES + " bytes");
            }
            copy.put(id.trim(), secret.clone());
        });
        String active = StringUtils.hasText(activeKeyId) ? activeKeyId.trim()
                : copy.size() == 1 ? copy.keySet().iterator().next() : null;
        if (active == null || !copy.containsKey(active)) {
            throw new IllegalArgumentException("The active evidence signing key " + activeKeyId + " is not configured");
        }
        this.keys = copy;
        this.activeKeyId = active;
        this.configured = configured;
    }

    /**
     * The signer of the configured Base64 keys; with none, a signer of one ephemeral key, reported as an error since
     * its signatures do not survive a restart.
     */
    public static HmacEvidenceSigner of(@Nullable Map<String, String> base64Keys, @Nullable String activeKeyId) {
        if (base64Keys == null || base64Keys.isEmpty()) {
            byte[] secret = new byte[MIN_KEY_BYTES];
            new SecureRandom().nextBytes(secret);
            String id = "ephemeral-" + HexFormat.of().formatHex(secret, 0, 4);
            log.warn("[EvidenceSigning] No evidence signing key configured (contexa.security.evidence.signing.keys) - "
                    + "using an ephemeral key {}. Decision records and sealed evidence signed now read as not "
                    + "verifiable after a restart; configure a persistent key.", id);
            return new HmacEvidenceSigner(Map.of(id, secret), id, false);
        }
        Map<String, byte[]> keys = new LinkedHashMap<>();
        base64Keys.forEach((id, value) -> {
            try {
                keys.put(id, Base64.getDecoder().decode(value == null ? "" : value.trim()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Evidence signing key " + id + " is not Base64", e);
            }
        });
        return new HmacEvidenceSigner(keys, activeKeyId);
    }

    @Override
    public String activeKeyId() {
        return activeKeyId;
    }

    @Override
    public boolean keepsItsKeys() {
        return configured;
    }

    @Override
    public String sign(String value) {
        return mac(keys.get(activeKeyId), value);
    }

    @Override
    @Nullable
    public Boolean verify(String keyId, String value, String signature) {
        byte[] secret = keyId != null ? keys.get(keyId.trim()) : null;
        if (secret == null || signature == null) {
            return null;
        }
        return MessageDigest.isEqual(mac(secret, value).getBytes(StandardCharsets.US_ASCII),
                signature.trim().getBytes(StandardCharsets.US_ASCII));
    }

    private static String mac(byte[] secret, String value) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret, ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal((value == null ? "" : value).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }
}
