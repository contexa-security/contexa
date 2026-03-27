package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public enum PromptBudgetProfile {
    CORTEX_L1_STANDARD("CORTEX_L1_STANDARD", "Security decision layer1 standard profile", 2000, 450, 1150, 400, false),
    CORTEX_L2_STANDARD("CORTEX_L2_STANDARD", "Security decision layer2 standard profile", 2600, 500, 1500, 600, true),
    CORTEX_L1_EXPANDED("CORTEX_L1_EXPANDED", "Security decision layer1 expanded profile", 2800, 500, 1700, 600, true),
    CORTEX_L2_EXPANDED("CORTEX_L2_EXPANDED", "Security decision layer2 expanded profile", 3600, 550, 2250, 800, true),
    CORTEX_ENTERPRISE_ENRICHED("CORTEX_ENTERPRISE_ENRICHED", "Security decision enterprise-enriched profile", 4200, 600, 2600, 1000, true);

    private final String profileKey;
    private final String description;
    private final int maxInputTokens;
    private final int systemReserveTokens;
    private final int userReserveTokens;
    private final int outputReserveTokens;
    private final boolean expansionAllowed;

    PromptBudgetProfile(
            String profileKey,
            String description,
            int maxInputTokens,
            int systemReserveTokens,
            int userReserveTokens,
            int outputReserveTokens,
            boolean expansionAllowed) {
        this.profileKey = profileKey;
        this.description = description;
        this.maxInputTokens = maxInputTokens;
        this.systemReserveTokens = systemReserveTokens;
        this.userReserveTokens = userReserveTokens;
        this.outputReserveTokens = outputReserveTokens;
        this.expansionAllowed = expansionAllowed;
    }

    public String profileKey() {
        return profileKey;
    }

    public String description() {
        return description;
    }

    public int maxInputTokens() {
        return maxInputTokens;
    }

    public int systemReserveTokens() {
        return systemReserveTokens;
    }

    public int userReserveTokens() {
        return userReserveTokens;
    }

    public int outputReserveTokens() {
        return outputReserveTokens;
    }

    public boolean expansionAllowed() {
        return expansionAllowed;
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("budgetProfile", profileKey);
        metadata.put("budgetProfileDescription", description);
        metadata.put("budgetMaxInputTokens", maxInputTokens);
        metadata.put("budgetSystemReserveTokens", systemReserveTokens);
        metadata.put("budgetUserReserveTokens", userReserveTokens);
        metadata.put("budgetOutputReserveTokens", outputReserveTokens);
        metadata.put("budgetExpansionAllowed", expansionAllowed);
        return metadata;
    }

    public static PromptBudgetProfile fromKey(String value, PromptBudgetProfile fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        for (PromptBudgetProfile profile : values()) {
            if (profile.profileKey.equalsIgnoreCase(normalized) || profile.name().equals(normalized)) {
                return profile;
            }
        }
        return fallback;
    }
}
