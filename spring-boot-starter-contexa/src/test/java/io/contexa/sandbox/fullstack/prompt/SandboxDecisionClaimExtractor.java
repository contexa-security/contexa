package io.contexa.sandbox.fullstack.prompt;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class SandboxDecisionClaimExtractor {

    public List<String> extract(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return List.of();
        }

        String normalized = reasoning
                .replace('\r', '\n')
                .replace(" but ", ". ");

        String[] rawClaims = normalized.split("[.!?;\\n]+");
        Set<String> claims = new LinkedHashSet<>();
        for (String rawClaim : rawClaims) {
            String claim = rawClaim == null ? "" : rawClaim.trim();
            if (claim.isBlank()) {
                continue;
            }
            if (claim.length() < 4) {
                continue;
            }
            claims.add(claim);
        }
        return new ArrayList<>(claims);
    }

    public boolean containsUncertaintyLanguage(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return false;
        }
        String normalized = reasoning.toLowerCase(Locale.ROOT);
        return normalized.contains("uncertain")
                || normalized.contains("provisional")
                || normalized.contains("sparse")
                || normalized.contains("limited")
                || normalized.contains("insufficient")
                || normalized.contains("missing baseline")
                || normalized.contains("missing evidence")
                || normalized.contains("lacks sufficient evidence")
                || normalized.contains("lack sufficient evidence")
                || normalized.contains("lacks evidence")
                || normalized.contains("fallback signal")
                || normalized.contains("fallback signals")
                || normalized.contains("thin evidence")
                || normalized.contains("thin role scope evidence")
                || normalized.contains("thin scope evidence")
                || normalized.contains("thin baseline evidence")
                || normalized.contains("thin history")
                || normalized.contains("no baseline")
                || normalized.contains("lack of")
                || normalized.contains("not enough");
    }
}
