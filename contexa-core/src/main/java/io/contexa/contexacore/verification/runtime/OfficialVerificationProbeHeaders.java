package io.contexa.contexacore.verification.runtime;

import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Transport-neutral header values for an official verification probe.
 */
public final class OfficialVerificationProbeHeaders {

    public static final String AUTHORIZATION = "Authorization";
    public static final String COOKIE = "Cookie";
    public static final String USER_AGENT = "User-Agent";
    public static final String ACCEPT = "Accept";
    public static final String FAULT_SCENARIO = "X-Contexa-Verification-Bridge-Fault-Scenario";
    public static final String FAULT_CAPABILITY = "X-Contexa-Verification-Bridge-Fault-Capability";
    public static final String RUNTIME_OVERRIDE_CAPABILITY = "X-Contexa-Verification-Runtime-Capability";

    private static final String FAULT_CAPABILITY_VALUE = UUID.randomUUID().toString();
    private static final String RUNTIME_OVERRIDE_CAPABILITY_VALUE = UUID.randomUUID().toString();

    private final Map<String, String> values = new LinkedHashMap<>();

    public void set(String name, String value) {
        if (StringUtils.hasText(name) && StringUtils.hasText(value)) {
            values.put(name.trim(), value.trim());
        }
    }

    public Map<String, String> asMap() {
        return Map.copyOf(values);
    }

    public void setAuthorizedFault(VerificationFaultScenario scenario) {
        if (scenario == null) {
            return;
        }
        set(FAULT_SCENARIO, scenario.type().name());
        set(FAULT_CAPABILITY, FAULT_CAPABILITY_VALUE);
    }

    /**
     * Marks this probe as issued by the current server so that the runtime override and
     * simulation headers it carries are honored when the probe request is analyzed.
     * The capability is scoped separately from the fault capability, so it never
     * authorizes prompt fault injection.
     */
    public void setRuntimeOverrideCapability() {
        set(RUNTIME_OVERRIDE_CAPABILITY, RUNTIME_OVERRIDE_CAPABILITY_VALUE);
    }

    public static boolean isAuthorizedFault(String scenario, String capability) {
        if (!StringUtils.hasText(scenario)) {
            return false;
        }
        return capabilityMatches(FAULT_CAPABILITY_VALUE, capability);
    }

    /**
     * Returns true only when the presented value equals the runtime override capability
     * issued by this JVM. Client supplied scenario markers or request paths never qualify.
     */
    public static boolean isAuthorizedRuntimeOverride(String capability) {
        return capabilityMatches(RUNTIME_OVERRIDE_CAPABILITY_VALUE, capability);
    }

    private static boolean capabilityMatches(String expected, String capability) {
        if (!StringUtils.hasText(capability)) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                capability.trim().getBytes(StandardCharsets.UTF_8));
    }

    public static void authorizeFaultMetadata(Map<String, Object> metadata, String scenario) {
        if (metadata == null || !StringUtils.hasText(scenario)) {
            return;
        }
        metadata.put("pqaPromptFaultEnabled", true);
        metadata.put("pqaPromptFaultScenario", scenario.trim());
        metadata.put("pqaPromptFaultCapability", FAULT_CAPABILITY_VALUE);
    }

    public static boolean consumeAuthorizedFaultMetadata(Map<String, Object> metadata, String scenario) {
        if (metadata == null || !StringUtils.hasText(scenario)) {
            return false;
        }
        Object rawCapability = metadata.remove("pqaPromptFaultCapability");
        boolean authorized = isAuthorizedFault(
                scenario,
                rawCapability == null ? null : String.valueOf(rawCapability));
        if (!authorized) {
            metadata.remove("pqaPromptFaultEnabled");
            metadata.remove("pqaPromptFaultScenario");
            metadata.remove("officialVerification.pqaPromptFaultScenario");
            metadata.put("pqaPromptFaultRejected", true);
            metadata.put("pqaPromptFaultRejectedSource", "UNTRUSTED_EVENT_METADATA");
        }
        return authorized;
    }
}
