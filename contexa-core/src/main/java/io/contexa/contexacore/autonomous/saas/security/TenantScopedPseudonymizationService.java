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
