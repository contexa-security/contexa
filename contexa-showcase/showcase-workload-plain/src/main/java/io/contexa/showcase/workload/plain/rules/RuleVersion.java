package io.contexa.showcase.workload.plain.rules;

import io.contexa.showcase.business.context.JdbcBusinessContextLookup;
import io.contexa.showcase.business.context.LookupPlan;
import io.contexa.showcase.business.work.RbacPolicy;
import io.contexa.showcase.workload.plain.security.ControlAuthorizationManager;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The published configuration of the rule controls and its hash, the execution specification's ruleVersion (plan
 * P2: freeze the rules before recording). The hash covers the rule values and the compiled classes that decide, so
 * any change to a threshold, a lookup or the role table gives a new version.
 */
public final class RuleVersion {

    static final List<Class<?>> DECIDING_CLASSES = List.of(ThresholdRules.class, ContextLookupRules.class,
            ControlAuthorizationManager.class, RbacPolicy.class, LookupPlan.class, JdbcBusinessContextLookup.class);

    private RuleVersion() {
    }

    public static Map<String, Object> describe() {
        Map<String, Object> thresholds = new LinkedHashMap<>();
        thresholds.put("nightStart", ThresholdRules.NIGHT_START.toString());
        thresholds.put("nightEnd", ThresholdRules.NIGHT_END.toString());
        thresholds.put("volumeLimit", ThresholdRules.VOLUME_LIMIT);
        thresholds.put("dormantWindowDays", ThresholdRules.DORMANT_WINDOW_DAYS);
        Map<String, Object> lookups = new LinkedHashMap<>();
        lookups.put("assignedExportLimit", ContextLookupRules.ASSIGNED_EXPORT_LIMIT);
        lookups.put("historyWindowDays", ContextLookupRules.HISTORY_WINDOW_DAYS);
        lookups.put("exportHistoryWindowDays", ContextLookupRules.EXPORT_HISTORY_WINDOW_DAYS);
        List<String> roles = RbacPolicy.RULES.stream()
                .map(rule -> rule.method() + " " + rule.pattern() + " " + rule.roles().stream().sorted().toList())
                .toList();
        Map<String, Object> description = new LinkedHashMap<>();
        description.put("c1", thresholds);
        description.put("c2", lookups);
        description.put("rbac", roles);
        description.put("sha256", sha256(description.toString()));
        return description;
    }

    private static String sha256(String canonical) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(canonical.getBytes(StandardCharsets.UTF_8));
            for (Class<?> type : DECIDING_CLASSES) {
                String resource = type.getName().replace('.', '/') + ".class";
                try (InputStream in = type.getClassLoader().getResourceAsStream(resource)) {
                    if (in == null) {
                        throw new IllegalStateException("Class file not found: " + resource);
                    }
                    digest.update(in.readAllBytes());
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
