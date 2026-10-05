package io.contexa.showcase.workload.plain.rules;

import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.BusinessContextLookup.AccessHistory;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Control C1, threshold rules over time, volume and dormancy (deck p.7). Draft values of ADR-22, frozen with a
 * hash before the P2 recordings. All rules are evaluated; the first violated one decides.
 */
public class ThresholdRules {

    public static final LocalTime NIGHT_START = LocalTime.of(22, 0);
    public static final LocalTime NIGHT_END = LocalTime.of(6, 0);
    public static final int VOLUME_LIMIT = 500;
    public static final int DORMANT_WINDOW_DAYS = 30;

    private final BusinessContextLookup lookup;

    public ThresholdRules(BusinessContextLookup lookup) {
        this.lookup = lookup;
    }

    public RuleDecision evaluate(RequestFacts request) {
        Map<String, Object> facts = new LinkedHashMap<>();
        LocalTime time = LocalTime.ofInstant(request.companyTime(), ZoneOffset.UTC);
        boolean night = !time.isBefore(NIGHT_START) || time.isBefore(NIGHT_END);
        facts.put("companyTime", request.companyTime().toString());
        facts.put("night", night);
        BusinessOperation operation = request.operation();
        boolean exporting = operation == BusinessOperation.EXPORT || operation == BusinessOperation.EXPORT_STREAM;
        if (exporting) {
            facts.put("items", request.items());
        }
        Integer accessDays = null;
        // Dormancy is a rule about project data (ADR-22); giving a role is not reading the project's data.
        if (request.projectKey() != null && operation != BusinessOperation.CUSTOMER_READ && !operation.privileged()) {
            AccessHistory history = lookup.historyDays(request.username(), request.projectKey(),
                    request.companyTime(), DORMANT_WINDOW_DAYS);
            accessDays = history.days();
            facts.put("projectKey", request.projectKey());
            facts.put("accessDaysLast30", history.days());
            facts.put("lastAccessDate", history.lastAccessDate());
        }
        if (operation.bulk() && night) {
            return RuleDecision.deny("C1-NIGHT", "Data hand-out at night (22:00-06:00 company time)", facts);
        }
        if (exporting && request.items() > VOLUME_LIMIT) {
            return RuleDecision.deny("C1-VOLUME", "Export of more than " + VOLUME_LIMIT + " items", facts);
        }
        if (accessDays != null && accessDays == 0) {
            return RuleDecision.deny("C1-DORMANT", "No access to the project in the last " + DORMANT_WINDOW_DAYS
                    + " days", facts);
        }
        return RuleDecision.allow("C1-PASS", "Within the time, volume and dormancy thresholds", facts);
    }
}
