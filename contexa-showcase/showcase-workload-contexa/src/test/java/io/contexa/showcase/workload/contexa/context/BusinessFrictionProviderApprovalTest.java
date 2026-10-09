package io.contexa.showcase.workload.contexa.context;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.showcase.business.context.AccessApprovalPolicy;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.ExportApprovalPolicy;
import io.contexa.showcase.business.work.BusinessOperation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The approval labels control D gives the engine come from the company's export approval policy row, the same row and
 * the same decision control C2 applies (docs/showcase/데모-재설계.md H-15): a fitting ticket with on-call duty, or the
 * assigned employee up to the assigned limit, lets an export through without approval; any other export needs one. A
 * legitimate on-call export (A8T, S03) must not reach the engine as "approval missing" (F-18). The policy in the stub
 * has the values of the business database's EXPORT_APPROVAL row (work migration V6).
 */
class BusinessFrictionProviderApprovalTest {

    private static final Instant AT = Instant.parse("2026-09-30T20:30:00Z");
    private static final String USER = "v0123456789ab-adm-a";
    private static final ExportApprovalPolicy POLICY = new ExportApprovalPolicy("EXPORT_APPROVAL",
            "An export of project documents needs an approval.", 500, true);
    /** The access rules of the business database (work migration V7, Q-A4). */
    private static final AccessApprovalPolicy GRANT_POLICY = new AccessApprovalPolicy("ROLE_GRANT_APPROVAL",
            "A role on a project is given only under an approved change ticket for that project.", false, false, null);
    private static final AccessApprovalPolicy CUSTOMER_POLICY = new AccessApprovalPolicy("CUSTOMER_ACCESS_APPROVAL",
            "A customer record is read by its account manager, or under a ticket that covers the customer's project.",
            true, false, null);

    @Test
    void aFittingTicketWithOnCallDutyNeedsNoApproval() {
        FrictionProfile profile = enrich(new Stub(false, false, true, true), 300);

        assertThat(profile.getApprovalRequired()).isFalse();
        assertThat(profile.getApprovalMissing()).isFalse();
    }

    @Test
    void aTicketWithoutOnCallDutyStillNeedsAnApproval() {
        FrictionProfile profile = enrich(new Stub(false, false, true, false), 300);

        assertThat(profile.getApprovalRequired()).isTrue();
        assertThat(profile.getApprovalMissing()).isTrue();
    }

    @Test
    void theAssignedEmployeeNeedsNoApprovalUpToTheAssignedLimit() {
        assertThat(enrich(new Stub(true, false, false, false), POLICY.assignedExportLimit())
                .getApprovalRequired()).isFalse();
        FrictionProfile above = enrich(new Stub(true, false, false, false), POLICY.assignedExportLimit() + 1);
        assertThat(above.getApprovalRequired()).isTrue();
        assertThat(above.getApprovalMissing()).isTrue();
    }

    @Test
    void aCoveringApprovalLeavesTheApprovalRequiredButNotMissing() {
        FrictionProfile profile = enrich(new Stub(false, true, false, false), 4831);

        assertThat(profile.getApprovalRequired()).isTrue();
        assertThat(profile.getApprovalMissing()).isFalse();
        assertThat(profile.getApprovalStatus()).isEqualTo("APPROVED");
        assertThat(profile.getApprovalDecisionAgeMinutes())
                .as("the record has no decision time, so no age is sent (survey D5)").isNull();
        assertThat(profile.getApprovalLineage()).anySatisfy(line -> assertThat(line)
                .contains("company policy EXPORT_APPROVAL (")
                .endsWith("requires an approval for this export: yes"));
    }

    /**
     * W2-5 (case S12): an approval whose decision was recorded after the request is told as such, with the minutes
     * between them and that its validity starts before the decision; no decision age clipped to zero is sent. A
     * decision recorded before the request gives its age.
     */
    @Test
    void anApprovalRecordedAfterTheRequestIsToldAsRecordedAfterIt() {
        FrictionProfile after = enrich(new Stub(false, true, false, false, Duration.ofMinutes(20)), 300);

        assertThat(after.getApprovalStatus()).isEqualTo("APPROVED");
        assertThat(after.getApprovalDecisionAgeMinutes()).isNull();
        assertThat(after.getApprovalLineage()).anySatisfy(line -> assertThat(line)
                .contains("approval APR-1 by pm-11")
                .endsWith("Its decision was recorded at " + AT.plus(Duration.ofMinutes(20)) + ", 20 minutes after this "
                        + "request, with a validity that starts before the decision was recorded."));

        FrictionProfile before = enrich(new Stub(false, true, false, false, Duration.ofMinutes(-45)), 300);
        assertThat(before.getApprovalDecisionAgeMinutes()).isEqualTo(45);
        assertThat(before.getApprovalLineage()).anySatisfy(line -> assertThat(line)
                .endsWith("Its decision was recorded at " + AT.minus(Duration.ofMinutes(45)) + ", before this request."));
    }

    /** Surveys D2, D3, D4: what is not known is said so, and the summary says whether anything was looked up. */
    @Test
    void anUnknownItemCountOrRequestTimeIsSaidSoAndNothingIsLookedUp() {
        FrictionProfile noItems = enrich(new Stub(true, true, true, true), "items=abc", AT);
        assertThat(noItems.getApprovalRequired()).isNull();
        assertThat(noItems.getApprovalLineage()).containsExactly(
                "The export names no valid item count; its company facts were not looked up.");
        assertThat(noItems.getSummary()).isEqualTo(
                "Company facts of this request were not looked up in the business database.");

        FrictionProfile noTime = enrich(new Stub(true, true, true, true), "items=40", null);
        assertThat(noTime.getApprovalLineage()).singleElement().asString().startsWith("The request time is unknown");
        assertThat(BusinessFrictionProvider.items("items=0")).isNull();
        assertThat(BusinessFrictionProvider.items(null)).isNull();
        assertThat(BusinessFrictionProvider.items("items=40")).isEqualTo(40);
    }

    /**
     * Q-A4: a role grant needs an approved change ticket, so the engine is told the approval is required, and missing
     * unless a ticket covers the grant (A5 against A5T).
     */
    @Test
    void aRoleGrantNeedsAnApprovedChangeTicket() {
        FrictionProfile missing = enrich(new Stub(false, false, false, false), "POST", "/api/admin/role-grants",
                "grantee=eng-k&project=GB-500&responsibility=REVIEW");
        assertThat(missing.getApprovalRequired()).isTrue();
        assertThat(missing.getApprovalMissing()).isTrue();
        assertThat(missing.getApprovalStatus()).isEqualTo("NO_COVERING_APPROVAL");
        assertThat(missing.getApprovalLineage()).anySatisfy(line -> assertThat(line)
                .contains("company policy ROLE_GRANT_APPROVAL (")
                .endsWith("requires an approval for this request: yes"));

        FrictionProfile covered = enrich(new Stub(false, false, true, false), "POST", "/api/admin/role-grants",
                "grantee=eng-k&project=GB-500&responsibility=REVIEW");
        assertThat(covered.getApprovalRequired()).isTrue();
        assertThat(covered.getApprovalMissing()).as("the change ticket is the approval record").isFalse();
        assertThat(covered.getApprovalStatus()).isEqualTo("APPROVED");
        assertThat(covered.getApprovalTicketId()).isEqualTo("TCK-1");
    }

    /** Q-A4: a customer record read by someone other than its account manager needs a covering ticket (A6). */
    @Test
    void aCustomerReadByAnotherEmployeeNeedsAnApproval() {
        FrictionProfile profile = enrich(new Stub(false, false, false, false), "GET", "/api/customers/CUS-0001",
                null);

        assertThat(profile.getApprovalRequired()).isTrue();
        assertThat(profile.getApprovalMissing()).isTrue();
        assertThat(profile.getApprovalLineage()).anySatisfy(line -> assertThat(line)
                .contains("company policy CUSTOMER_ACCESS_APPROVAL (")
                .endsWith("requires an approval for this request: yes"));
    }

    private static FrictionProfile enrich(Stub lookup, int items) {
        return enrich(lookup, "items=" + items, AT);
    }

    private static FrictionProfile enrich(Stub lookup, String query, Instant at) {
        return enrich(lookup, "POST", "/api/projects/GB-500/exports", query, at);
    }

    private static FrictionProfile enrich(Stub lookup, String method, String path, String query) {
        return enrich(lookup, method, path, query, AT);
    }

    private static FrictionProfile enrich(Stub lookup, String method, String path, String query, Instant at) {
        SecurityEvent event = SecurityEvent.builder().userId(USER)
                .timestamp(at == null ? null : LocalDateTime.ofInstant(at, ZoneOffset.UTC)).build();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestPath", path);
        metadata.put("httpMethod", method);
        metadata.put("queryString", query);
        event.setMetadata(metadata);
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        new BusinessFrictionProvider(lookup, null).enrich(event, context);
        assertThat(context.getFrictionProfile()).as("the provider wrote the company facts").isNotNull();
        return context.getFrictionProfile();
    }

    /** The company facts of one export, as the shared business lookup would return them. */
    private record Stub(boolean assigned, boolean approved, boolean ticket, boolean onCall, Duration decidedAfter)
            implements BusinessContextLookup {

        Stub(boolean assigned, boolean approved, boolean ticket, boolean onCall) {
            this(assigned, approved, ticket, onCall, null);
        }

        @Override
        public Optional<RunPrincipal> principal(String username) {
            return Optional.of(new RunPrincipal(username, "run-test", "adm-a", "ADMIN", "org-test", "tenant-test"));
        }

        @Override
        public TicketCoverage ticketCovers(String username, String projectKey, BusinessOperation operation,
                                           Instant at) {
            return ticket ? new TicketCoverage(true, "TCK-1", "pm-11", "INCIDENT_RECOVERY", at.minusSeconds(3600),
                    at.plusSeconds(3600), List.of()) : TicketCoverage.none();
        }

        @Override
        public OncallStatus oncallHas(String username, Instant at) {
            return new OncallStatus(onCall, onCall ? "RST-1" : null, onCall ? "PLATFORM" : null,
                    onCall ? at.minusSeconds(3600) : null, onCall ? at.plusSeconds(3600) : null);
        }

        @Override
        public AssignmentStatus projectAssigned(String username, String projectKey, Instant at) {
            return new AssignmentStatus(assigned, assigned ? "OWNER" : null);
        }

        @Override
        public ApprovalCoverage approvalExists(String username, String projectKey, int items, Instant at) {
            return approved ? new ApprovalCoverage(true, "APR-1", "pm-11", "PROJECT_TRANSFER", 5000,
                    at.minusSeconds(3600), at.plusSeconds(3600), List.of(),
                    decidedAfter == null ? null : at.plus(decidedAfter)) : ApprovalCoverage.none();
        }

        @Override
        public ExportApprovalPolicy exportApprovalPolicy() {
            return POLICY;
        }

        @Override
        public AccessApprovalPolicy accessApprovalPolicy(BusinessOperation operation) {
            return switch (operation) {
                case ROLE_GRANT -> GRANT_POLICY;
                case CUSTOMER_READ -> CUSTOMER_POLICY;
                default -> throw new IllegalArgumentException("No access approval policy for " + operation);
            };
        }

        @Override
        public AccessHistory historyDays(String username, String projectKey, Instant at, int windowDays) {
            return new AccessHistory(0, windowDays, null);
        }

        @Override
        public CustomerOwnership customerOwner(String username, String customerKey) {
            return new CustomerOwnership(false, customerKey, null, null);
        }

        @Override
        public ClaimCheck claimedTicket(String username, String ticketKey, String projectKey,
                                        BusinessOperation operation, Instant at) {
            return new ClaimCheck(ticketKey, false, TicketCoverage.none());
        }

        @Override
        public NetworkContext networkContext(String username, String clientIp, Instant at) {
            return new NetworkContext(NetworkKind.OFFICE, clientIp, "10.40.12.0/24", null, null, null);
        }
    }
}
