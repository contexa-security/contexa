package io.contexa.showcase.workload.plain.rules;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Instant;

/**
 * Decides a recorded request again with the rule classes themselves under given settings (H-10): each control's own
 * recorded facts answer its lookups, so control C1 and control C2 see exactly what they saw when the request ran.
 */
public final class RecordedRuleEvaluation {

    /**
     * A recorded request of a run.
     *
     * @param c1Facts the facts control C1 recorded (JSON text as stored), or null when it recorded none
     * @param c2Facts the facts control C2 recorded (JSON text as stored), or null when it recorded none
     */
    public record Step(String operation, String username, Instant companyTime, String c1Facts, String c2Facts) {
    }

    /**
     * One control's decision; when the request's records lack a fact the rule needs, only {@code notRecorded} is set.
     */
    public record Decision(String ruleId, Boolean allowed, String notRecorded) {
    }

    public record Result(Decision c1, Decision c2) {
    }

    private RecordedRuleEvaluation() {
    }

    public static Result evaluate(Step step, RuleSettings settings, ObjectMapper json) {
        BusinessOperation operation = BusinessOperation.valueOf(step.operation());
        JsonNode c1 = facts(step.c1Facts(), json);
        JsonNode c2 = facts(step.c2Facts(), json);
        Decision threshold = decide(() -> new ThresholdRules(new RecordedFactsLookup(c1, json))
                .evaluate(request(operation, step, c1), settings));
        Decision context = decide(() -> new ContextLookupRules(new RecordedFactsLookup(c2, json))
                .evaluate(request(operation, step, c2), settings));
        return new Result(threshold, context);
    }

    private interface Rule {
        RuleDecision decide();
    }

    private static Decision decide(Rule rule) {
        try {
            RuleDecision decision = rule.decide();
            return new Decision(decision.ruleId(), decision.allowed(), null);
        } catch (RecordedFactsLookup.NotRecorded e) {
            return new Decision(null, null, e.fact());
        }
    }

    /**
     * The request as one control saw it, from what that control recorded: the project, the item count, the customer
     * or grantee, the ticket the request named and the requester's address.
     */
    static RequestFacts request(BusinessOperation operation, Step step, JsonNode facts) {
        String projectKey = text(facts.get("projectKey"));
        if (projectKey == null) {
            projectKey = text(facts.path("customer").get("projectKey"));
        }
        String targetKey = text(facts.path("customer").get("customerKey"));
        if (targetKey == null) {
            targetKey = text(facts.get("grantee"));
        }
        JsonNode items = facts.get("items");
        return new RequestFacts(operation, step.username(), targetKey, projectKey,
                items != null && items.isNumber() ? items.asInt() : null, step.companyTime(),
                text(facts.path("claim").get("ticketKey")), text(facts.path("network").get("clientIp")));
    }

    private static String text(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }

    private static JsonNode facts(String text, ObjectMapper json) {
        if (text == null || text.isBlank()) {
            return json.createObjectNode();
        }
        try {
            return json.readTree(text);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Unreadable recorded facts", e);
        }
    }
}
