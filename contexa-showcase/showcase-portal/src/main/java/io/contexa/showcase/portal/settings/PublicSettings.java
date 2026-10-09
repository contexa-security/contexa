package io.contexa.showcase.portal.settings;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.anatomy.CoreAdverseLabels;

import java.util.ArrayList;
import java.util.List;

/**
 * The demo's real settings of the five approaches and its retention periods, as the screens show them (G3's settings
 * window and the adoption screen, 7.4 of docs/showcase/화면설계서-v2-구현계획.md). Every value is copied from where the
 * running stack keeps it: the plain workload's published rules, the engine's published facts, the portal's own
 * retention plan and the WAF image the stack runs. A value a source does not state is null, never filled in.
 */
public final class PublicSettings {

    /**
     * @param image   the WAF container image the stack runs, as configured for the portal; null when not configured
     * @param ruleSet the rule set it runs and how, as configured; null when not configured
     */
    public record Waf(String image, String ruleSet) {
    }

    /** @param roleRules the role check's rules as the plain workload publishes them: method, path pattern, roles */
    public record Permission(List<String> roleRules) {
    }

    public record Threshold(String nightStart, String nightEnd, Integer volumeLimit, Integer dormantWindowDays) {
    }

    public record AccessPolicy(String policyKey, boolean accountManagerExempt, boolean assignedExempt,
                               Integer recentWorkDays) {
    }

    /**
     * @param exportPolicyKey         the company's export approval policy
     * @param assignedExportLimit     the largest export of an assigned project that needs no approval
     * @param ticketAndOncallExempt   whether a covering ticket while on call stands in for an approval
     * @param historyWindowDays       how far back the access history is read
     * @param exportHistoryWindowDays how far back the export history is read
     */
    public record BusinessRecord(String exportPolicyKey, Integer assignedExportLimit, Boolean ticketAndOncallExempt,
                                 Integer historyWindowDays, Integer exportHistoryWindowDays,
                                 List<AccessPolicy> accessPolicies) {
    }

    /**
     * @param effectiveMode       the engine's zero-trust mode as it runs (ENFORCE, SHADOW, DISABLED)
     * @param inspectorConditions how many adverse conditions the core's response inspector checks in every answer (the
     *                            label contract kept equal to the core by CoreAdverseLabelsContractTest)
     */
    public record Engine(String chatModel, String effectiveMode, int inspectorConditions) {
    }

    /**
     * @param behaviorDays       how long the engine keeps behaviour documents; null when the engine does not state it
     * @param promptOriginalDays how long the portal keeps the prompt and answer texts of model calls
     */
    public record Retention(Integer behaviorDays, int promptOriginalDays) {
    }

    /** @param ruleVersion the hash the plain workload publishes over these rules */
    public record View(Waf waf, Permission permission, Threshold threshold, BusinessRecord businessRecord,
                       Engine engine, Retention retention, String ruleVersion) {
    }

    private PublicSettings() {
    }

    /**
     * @param rules  the plain workload's published rules (/internal/rules)
     * @param engine the engine's published facts (/internal/engine)
     */
    public static View of(JsonNode rules, JsonNode engine, Waf waf, int promptOriginalDays) {
        JsonNode c1 = rules.path("c1");
        JsonNode c2 = rules.path("c2");
        JsonNode export = c2.path("exportApprovalPolicy");
        List<AccessPolicy> access = new ArrayList<>();
        c2.path("accessApprovalPolicies").forEach(row -> access.add(new AccessPolicy(text(row, "policyKey"),
                row.path("accountManagerExempt").asBoolean(), row.path("assignedExempt").asBoolean(),
                integer(row, "recentWorkDays"))));
        List<String> roleRules = new ArrayList<>();
        rules.path("rbac").forEach(rule -> roleRules.add(rule.asText()));
        return new View(waf, new Permission(List.copyOf(roleRules)),
                new Threshold(text(c1, "nightStart"), text(c1, "nightEnd"), integer(c1, "volumeLimit"),
                        integer(c1, "dormantWindowDays")),
                new BusinessRecord(text(export, "policyKey"), integer(export, "assignedExportLimit"),
                        export.has("ticketAndOncallExempt") ? export.path("ticketAndOncallExempt").asBoolean() : null,
                        integer(c2, "historyWindowDays"), integer(c2, "exportHistoryWindowDays"),
                        List.copyOf(access)),
                new Engine(text(engine, "chatModel"), text(engine, "effectiveMode"), CoreAdverseLabels.RULES.size()),
                new Retention(integer(engine, "behaviorRetentionDays"), promptOriginalDays), text(rules, "sha256"));
    }

    private static String text(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.path(field).asText() : null;
    }

    private static Integer integer(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.path(field).asInt() : null;
    }
}
