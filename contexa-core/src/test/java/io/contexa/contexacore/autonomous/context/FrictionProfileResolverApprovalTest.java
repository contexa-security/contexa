package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.resolver.FrictionProfileResolver;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** W1-8: approval missing means that no valid approval covers the request. */
class FrictionProfileResolverApprovalTest {

    @ParameterizedTest
    @CsvSource({
            "REJECTED, true", "PENDING, true", "EXPIRED, true", "CANCELLED, true", "MISSING, true", "NOT_FOUND, true",
            "APPROVED, false", "granted, false", "COMPLETED, false"})
    @DisplayName("only a granted approval covers a request that needs one")
    void onlyAGrantedApprovalCoversTheRequest(String status, boolean missing) {
        CanonicalSecurityContext.FrictionProfile profile = resolve(Map.of("approvalRequired", true, "approvalStatus", status));

        assertThat(profile.getApprovalMissing()).isEqualTo(missing);
        assertThat(profile.getApprovalGranted()).isEqualTo(!missing);
    }

    @Test
    @DisplayName("an unknown approval state leaves the approval unknown")
    void unknownStateIsUnknown() {
        CanonicalSecurityContext.FrictionProfile profile = resolve(Map.of("approvalRequired", true, "approvalStatus", "UNKNOWN"));

        assertThat(profile.getApprovalMissing()).isNull();
        assertThat(profile.getApprovalGranted()).isNull();
    }

    @Test
    @DisplayName("a request that needs no approval is not missing one")
    void noApprovalNeeded() {
        assertThat(resolve(Map.of("approvalRequired", false, "approvalStatus", "REJECTED")).getApprovalMissing()).isFalse();
    }

    @Test
    @DisplayName("the approval need is read the same way as every other truth value")
    void approvalNeedReadAsYes() {
        CanonicalSecurityContext.FrictionProfile profile = resolve(Map.of("approvalRequired", "yes", "approvalStatus", "PENDING"));

        assertThat(profile.getApprovalRequired()).isTrue();
        assertThat(profile.getApprovalMissing()).isTrue();
    }

    private static final Instant AT = Instant.parse("2026-09-30T14:20:00Z");

    @Test
    @DisplayName("an approval decided after the request does not grant it, whatever the host said")
    void anApprovalDecidedAfterTheRequestDoesNotGrantIt() {
        // W2-5, case S12: the host found the approval covering and set the simple fields from that.
        CanonicalSecurityContext.FrictionProfile host = hostSaysCovered(CanonicalSecurityContext.ApprovalRecord.builder()
                .approvalId("APR-1").status("APPROVED").target("GB-500").maxItems(500)
                .validFrom(AT.minus(Duration.ofHours(2))).validUntil(AT.plus(Duration.ofDays(1)))
                .decidedAt(AT.plus(Duration.ofMinutes(20))).hostCovers(true).build());

        CanonicalSecurityContext.FrictionProfile profile = resolveAt(host, 300, Map.of());

        assertThat(profile.getApprovalGranted()).isFalse();
        assertThat(profile.getApprovalMissing()).isTrue();
        assertThat(profile.getApprovalStatus()).isEqualTo("NO_COVERING_APPROVAL");
        assertThat(profile.getApprovalTicketId()).isNull();
        assertThat(profile.getApprovalRecords().get(0).getHostCovers()).isTrue();
    }

    @Test
    @DisplayName("what the session already exported under an approval counts against its limit")
    void whatTheSessionAlreadyExportedCountsAgainstTheApproval() {
        // W2-5, case S11: the second export of 480 items under an approval of 500.
        CanonicalSecurityContext.ApprovalRecord approval = CanonicalSecurityContext.ApprovalRecord.builder()
                .approvalId("APR-1").status("APPROVED").target("GB-500").maxItems(500)
                .validFrom(AT.minus(Duration.ofDays(1))).validUntil(AT.plus(Duration.ofDays(1))).hostCovers(true)
                .build();
        List<SessionDecisionRecord> session = List.of(new SessionDecisionRecord(AT.minusSeconds(60), "POST",
                "/api/projects/GB-500/exports", null, "EXPORT", "ALLOW", "projectKey=GB-500", 480));

        CanonicalSecurityContext.FrictionProfile first = resolveAt(hostSaysCovered(approval), 480, Map.of());
        CanonicalSecurityContext.FrictionProfile second = resolveAt(hostSaysCovered(approval), 480,
                Map.of(SessionDecisionRecord.METADATA_KEY, session));

        // The first export fits the limit, but the approval's use outside this session is not reported: neither
        // granted nor missing, the host's status stays (P2 correction 3).
        assertThat(first.getApprovalGranted()).isNull();
        assertThat(first.getApprovalMissing()).isNull();
        assertThat(first.getApprovalStatus()).isEqualTo("APPROVED");
        assertThat(first.getApprovalTicketId()).isEqualTo("APR-1");
        // The kinds the host looked up are carried with its records.
        assertThat(first.getCheckedRecordKinds()).containsExactly("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL",
                "ACCESS_HISTORY", "TRAVEL");
        assertThat(second.getApprovalGranted()).isFalse();
        assertThat(second.getApprovalMissing()).isTrue();

        // With the host's count of what was used, the first export is covered.
        approval.setUsedItems(0);
        CanonicalSecurityContext.FrictionProfile counted = resolveAt(hostSaysCovered(approval), 480, Map.of());
        assertThat(counted.getApprovalGranted()).isTrue();
        assertThat(counted.getApprovalMissing()).isFalse();
    }

    @Test
    @DisplayName("a ticket and the on-call roster cover an export the host left without an approval")
    void aTicketWhileOnCallCoversTheExport() {
        // W2-5, case S03 second step: the host said no approval is required and stated no grant.
        CanonicalSecurityContext.FrictionProfile host = CanonicalSecurityContext.FrictionProfile.builder()
                .approvalRequired(false).approvalGranted(false).approvalMissing(false)
                .approvalStatus("NO_COVERING_APPROVAL")
                .ticketRecords(new ArrayList<>(List.of(CanonicalSecurityContext.TicketRecord.builder().ticketId("TCK-1")
                        .target("GB-500").validFrom(AT.minus(Duration.ofHours(1)))
                        .validUntil(AT.plus(Duration.ofHours(4))).hostCovers(true).build())))
                .onCall(CanonicalSecurityContext.OnCallRecord.builder().onCall(true)
                        .startsAt(AT.minus(Duration.ofHours(2))).endsAt(AT.plus(Duration.ofHours(6))).build())
                .policies(new ArrayList<>(List.of(exportPolicy())))
                .build();

        CanonicalSecurityContext.FrictionProfile profile = resolveAt(host, 2, Map.of());

        assertThat(profile.getApprovalGranted()).isTrue();
        assertThat(profile.getApprovalStatus()).isEqualTo("APPROVED");
        assertThat(profile.getApprovalTicketId()).isEqualTo("TCK-1");
        assertThat(profile.getApprovalMissing()).isFalse();
        assertThat(profile.getApprovalRequired()).isFalse();
    }

    @Test
    @DisplayName("a pending approval keeps its state and leaves the needed approval missing")
    void aPendingApprovalKeepsItsState() {
        CanonicalSecurityContext.FrictionProfile host = CanonicalSecurityContext.FrictionProfile.builder()
                .approvalRequired(true).approvalStatus("PENDING").approvalTicketId("SOAR-7")
                .approvalRecords(new ArrayList<>(List.of(CanonicalSecurityContext.ApprovalRecord.builder()
                        .approvalId("SOAR-7").status("PENDING").build())))
                .build();

        CanonicalSecurityContext.FrictionProfile profile = resolveAt(host, null, Map.of());

        assertThat(profile.getApprovalStatus()).isEqualTo("PENDING");
        assertThat(profile.getApprovalGranted()).isFalse();
        assertThat(profile.getApprovalMissing()).isTrue();
        assertThat(profile.getApprovalTicketId()).isNull();
    }

    private static CanonicalSecurityContext.FrictionProfile hostSaysCovered(
            CanonicalSecurityContext.ApprovalRecord approval) {
        return CanonicalSecurityContext.FrictionProfile.builder()
                .approvalRequired(true).approvalGranted(true).approvalMissing(false).approvalStatus("APPROVED")
                .approvalTicketId(approval.getApprovalId())
                .approvalRecords(new ArrayList<>(List.of(approval)))
                .policies(new ArrayList<>(List.of(exportPolicy())))
                .checkedRecordKinds(new ArrayList<>(List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL")))
                .build();
    }

    private static CanonicalSecurityContext.CompanyPolicy exportPolicy() {
        return CanonicalSecurityContext.CompanyPolicy.builder().policyId("EXPORT_APPROVAL").requirement("APPROVAL")
                .exceptions(new ArrayList<>(List.of(
                        CanonicalSecurityContext.PolicyException.builder().kind("ASSIGNED").limit(500).build(),
                        CanonicalSecurityContext.PolicyException.builder().kind("TICKET_WHILE_ON_CALL").build())))
                .build();
    }

    private static CanonicalSecurityContext.FrictionProfile resolveAt(CanonicalSecurityContext.FrictionProfile host,
                                                                      Integer items, Map<String, Object> metadata) {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .requestObservedAt(AT)
                .resource(CanonicalSecurityContext.Resource.builder().pathFamily("/api/projects/{projectKey}/exports")
                        .requestPath("/api/projects/GB-500/exports").requestedItems(items).build())
                .build();
        context.setFrictionProfile(host);
        return new FrictionProfileResolver().resolve(new HashMap<>(metadata), context).orElseThrow();
    }

    private static CanonicalSecurityContext.FrictionProfile resolve(Map<String, Object> metadata) {
        return new FrictionProfileResolver()
                .resolve(new HashMap<>(metadata), CanonicalSecurityContext.builder().build())
                .orElseThrow();
    }
}
