package io.contexa.showcase.workload.plain.rules;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.context.AccessApprovalPolicy;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.ExportApprovalPolicy;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Instant;
import java.util.Optional;

/**
 * Answers the rules' lookups from the facts one control recorded for a request instead of the business database
 * (H-10): the rule classes then decide a past request again under other settings, over exactly what they saw then.
 * A lookup the request did not record is not guessed; it fails with {@link NotRecorded}.
 */
public class RecordedFactsLookup implements BusinessContextLookup {

    /** A rule asked for a fact the control did not record for this request. */
    public static class NotRecorded extends RuntimeException {

        private final String fact;

        public NotRecorded(String fact) {
            super("Fact not recorded: " + fact);
            this.fact = fact;
        }

        public String fact() {
            return fact;
        }
    }

    private final JsonNode facts;
    private final ObjectMapper json;

    public RecordedFactsLookup(JsonNode facts, ObjectMapper json) {
        this.facts = facts;
        this.json = json.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private <T> T read(String field, Class<T> type) {
        JsonNode node = facts.get(field);
        if (node == null || node.isNull()) {
            throw new NotRecorded(field);
        }
        try {
            return json.treeToValue(node, type);
        } catch (JsonProcessingException e) {
            throw new NotRecorded(field);
        }
    }

    @Override
    public Optional<RunPrincipal> principal(String username) {
        return Optional.empty();
    }

    @Override
    public TicketCoverage ticketCovers(String username, String projectKey, BusinessOperation operation, Instant at) {
        return read("ticket", TicketCoverage.class);
    }

    @Override
    public OncallStatus oncallHas(String username, Instant at) {
        return read("oncall", OncallStatus.class);
    }

    @Override
    public AssignmentStatus projectAssigned(String username, String projectKey, Instant at) {
        return read("assigned", AssignmentStatus.class);
    }

    @Override
    public ApprovalCoverage approvalExists(String username, String projectKey, int items, Instant at) {
        return read("approval", ApprovalCoverage.class);
    }

    @Override
    public ExportApprovalPolicy exportApprovalPolicy() {
        return read("policy", ExportApprovalPolicy.class);
    }

    @Override
    public AccessApprovalPolicy accessApprovalPolicy(BusinessOperation operation) {
        return read("policy", AccessApprovalPolicy.class);
    }

    /** The control recorded the days with access within the window it asked for, under accessDaysLast{window}. */
    @Override
    public AccessHistory historyDays(String username, String projectKey, Instant at, int windowDays) {
        String field = "accessDaysLast" + windowDays;
        JsonNode days = facts.get(field);
        if (days == null || !days.isNumber()) {
            throw new NotRecorded(field);
        }
        JsonNode last = facts.get("lastAccessDate");
        return new AccessHistory(days.asInt(), windowDays, last != null && last.isTextual() ? last.asText() : null);
    }

    @Override
    public CustomerOwnership customerOwner(String username, String customerKey) {
        return read("customer", CustomerOwnership.class);
    }

    @Override
    public ClaimCheck claimedTicket(String username, String ticketKey, String projectKey, BusinessOperation operation,
                                    Instant at) {
        return read("claim", ClaimCheck.class);
    }

    @Override
    public NetworkContext networkContext(String username, String clientIp, Instant at) {
        return read("network", NetworkContext.class);
    }
}
