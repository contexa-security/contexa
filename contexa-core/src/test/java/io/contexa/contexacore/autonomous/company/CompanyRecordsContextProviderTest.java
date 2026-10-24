/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.company;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.AccessDay;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Approval;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Assignment;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.NetworkZone;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.OnCall;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Person;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Policy;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Ticket;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Travel;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Usage;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent OC-2: a request is judged with the company records of the person who answers for it. */
class CompanyRecordsContextProviderTest {

    private static final Instant AT = Instant.parse("2026-09-30T05:30:00Z");
    private static final String ALICE = "alice";
    private static final String OFFICE_IP = "10.40.12.77";
    private static final String TRIP_IP = "198.51.100.20";
    private static final String OUTSIDE_IP = "203.0.113.9";

    private final InMemoryCompanyRecordStore store = new InMemoryCompanyRecordStore();
    private final CompanyRecordsContextProvider provider = new CompanyRecordsContextProvider(store);

    CompanyRecordsContextProviderTest() {
        store.put(null, new CompanyRecordSet(null,
                List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "TRAVEL", "ACCESS_HISTORY"), null, null, null,
                null, null, null, null, List.of(
                new Policy("EXPORT_APPROVAL", "An export needs an approval.", "APPROVAL", null, List.of("EXPORT"),
                        List.of("PROJECT_DOCUMENTS"), List.of(new Policy.Rule("ASSIGNED", 500),
                        new Policy.Rule("TICKET_WHILE_ON_CALL", null)),
                        List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL"), 30),
                new Policy("DOCUMENT_ACCESS_APPROVAL", "A document is read by an assigned person.", "TICKET", null,
                        List.of("READ", "DOWNLOAD"), List.of("PROJECT_DOCUMENTS"), List.of(
                        new Policy.Rule("ASSIGNED", null), new Policy.Rule("RECENT_WORK", 90)), null, null),
                new Policy("CUSTOMER_ACCESS_APPROVAL", "A customer is read by its account manager.", "TICKET", null,
                        List.of("READ"), List.of("CUSTOMER_RECORDS"), List.of(
                        new Policy.Rule("ACCOUNT_MANAGER", null)), null, null),
                new Policy("ROLE_GRANT_APPROVAL", "A role is given under a change ticket.", "TICKET", "CHANGE",
                        List.of("ADMIN"), List.of("PROJECT_ACCESS"), null, null, null)),
                List.of(new NetworkZone("10.40.12.0/24", "CORPORATE"))), "integration", AT.minusSeconds(3600));
    }

    @Test
    void anAssignedExportWithinTheLimitNeedsNoApprovalAndStatesEveryLookedUpRecord() {
        person(new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", "Alice")), null,
                List.of(new Assignment(ALICE, "HX-310", "DESIGN", LocalDate.parse("2026-01-01"), null)), null, null,
                null, null, List.of(new AccessDay(ALICE, "HX-310", LocalDate.parse("2026-09-29")),
                new AccessDay(ALICE, "HX-310", LocalDate.parse("2026-08-01"))), null, null, null));

        CanonicalSecurityContext context = enrich(export(ALICE, "HX-310", 300, OFFICE_IP));
        FrictionProfile profile = context.getFrictionProfile();

        assertThat(profile.getPolicies()).singleElement().satisfies(policy -> {
            assertThat(policy.getPolicyId()).isEqualTo("EXPORT_APPROVAL");
            assertThat(policy.getRequirement()).isEqualTo("APPROVAL");
            assertThat(policy.getHostRequires()).isFalse();
            assertThat(policy.getExceptions()).extracting(CanonicalSecurityContext.PolicyException::getKind)
                    .containsExactly("ASSIGNED", "TICKET_WHILE_ON_CALL");
        });
        assertThat(profile.getAssignment().getAssigned()).isTrue();
        assertThat(profile.getAssignment().getResponsibility()).isEqualTo("DESIGN");
        assertThat(profile.getAccessHistory().getDays()).isEqualTo(1);
        assertThat(profile.getAccessHistory().getWindowDays()).isEqualTo(30);
        assertThat(profile.getAccessHistory().getLastAccessDate()).isEqualTo("2026-09-29");
        assertThat(profile.getOnCall().getOnCall()).isFalse();
        assertThat(profile.getApprovalRecords()).isEmpty();
        assertThat(profile.getTicketRecords()).isEmpty();
        assertThat(profile.getCheckedRecordKinds())
                .containsExactly("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY", "TRAVEL");
        assertThat(profile.getApprovalRequired()).isFalse();
        assertThat(profile.getApprovalMissing()).isFalse();
        assertThat(profile.getApprovalStatus()).isEqualTo("NO_COVERING_APPROVAL");
        assertThat(profile.getRecordsHolderId()).isEqualTo(ALICE);
        assertThat(context.getLocation().getNetworkZone()).isEqualTo("CORPORATE");
        assertThat(profile.getTravel()).isNull();

        FrictionProfile above = enrich(export(ALICE, "HX-310", 501, OFFICE_IP)).getFrictionProfile();
        assertThat(above.getApprovalRequired()).isTrue();
        assertThat(above.getApprovalMissing()).isTrue();
    }

    @Test
    void theClosestApprovalIsStatedWithItsMismatchesAndWhatWasDeliveredUnderIt() {
        Instant from = AT.minus(Duration.ofDays(1));
        person(new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", null)), null, null, List.of(
                new Approval("APR-1", ALICE, "eng-k", "HX-310", "DATA_EXPORT", null, 2000, "APPROVED", from,
                        AT.plus(Duration.ofDays(1)), null, true, null, null),
                new Approval("APR-2", ALICE, "pm-11", "HX-310", "DATA_EXPORT", null, 2000, "APPROVED", from,
                        AT.plus(Duration.ofDays(1)), AT.minus(Duration.ofMinutes(45)), true, "pm-11",
                        AT.minus(Duration.ofMinutes(45)))), null, null, null, null,
                List.of(new Usage("job-1", ALICE, "HX-310", 600, AT.minus(Duration.ofHours(2))),
                        new Usage("job-0", ALICE, "HX-310", 900, from.minus(Duration.ofHours(1))),
                        new Usage("job-2", ALICE, "GB-500", 50, AT.minus(Duration.ofHours(1)))), null, null));

        FrictionProfile profile = enrich(export(ALICE, "HX-310", 1200, OUTSIDE_IP)).getFrictionProfile();

        assertThat(profile.getApprovalRecords()).singleElement().satisfies(record -> {
            assertThat(record.getApprovalId()).isEqualTo("APR-2");
            assertThat(record.getStatus()).isEqualTo("APPROVED");
            assertThat(record.getTarget()).isEqualTo("HX-310");
            assertThat(record.getMaxItems()).isEqualTo(2000);
            assertThat(record.getUsedItems()).as("only HX-310 within the validity before the request").isEqualTo(600);
            assertThat(record.getRecordedBy()).isEqualTo("pm-11");
            assertThat(record.getHostCovers()).isTrue();
            assertThat(record.getHostMismatches()).isEmpty();
        });
        assertThat(profile.getApprovalGranted()).isTrue();
        assertThat(profile.getApprovalTicketId()).isEqualTo("APR-2");
        assertThat(profile.getApprovalDecisionAgeMinutes()).isEqualTo(45);
        assertThat(profile.getApprovalMissing()).isFalse();

        FrictionProfile overLimit = enrich(export(ALICE, "HX-310", 2500, OUTSIDE_IP)).getFrictionProfile();
        assertThat(overLimit.getApprovalRecords()).singleElement().satisfies(record -> {
            assertThat(record.getApprovalId()).as("one mismatch against two").isEqualTo("APR-2");
            assertThat(record.getHostCovers()).isFalse();
            assertThat(record.getHostMismatches()).containsExactly("ITEMS");
        });
        assertThat(overLimit.getApprovalMissing()).isTrue();
    }

    @Test
    void aTicketCoversOnlyTheActionsItsPurposeCoversAndAClaimedTicketIsChecked() {
        person(new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", null)), null, null, null, List.of(
                new Ticket("TCK-1", ALICE, "CHANGE", "pm-11", "HX-310", "DESIGN_CHANGE", List.of("READ"), "OPEN",
                        AT.minus(Duration.ofHours(1)), AT.plus(Duration.ofHours(1)), null, null),
                new Ticket("TCK-2", ALICE, "INCIDENT", "pm-11", "GB-500", "INCIDENT_RECOVERY",
                        List.of("READ", "DOWNLOAD", "EXPORT"), "CLOSED", AT.minus(Duration.ofDays(9)),
                        AT.minus(Duration.ofDays(8)), null, null)), null, null, null, null, null, null));

        FrictionProfile read = enrich(document(ALICE, "READ", "HX-310")).getFrictionProfile();
        assertThat(read.getTicketRecords()).singleElement().satisfies(ticket -> {
            assertThat(ticket.getTicketId()).isEqualTo("TCK-1");
            assertThat(ticket.getKind()).isEqualTo("CHANGE");
            assertThat(ticket.getTarget()).isEqualTo("HX-310");
            assertThat(ticket.getHostCovers()).isTrue();
        });
        assertThat(read.getApprovalRequired()).as("not assigned, no recent work").isTrue();
        assertThat(read.getApprovalMissing()).isFalse();
        assertThat(read.getApprovalTicketId()).isEqualTo("TCK-1");
        assertThat(read.getCheckedRecordKinds()).containsExactly("ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL");

        FrictionProfile download = enrich(document(ALICE, "DOWNLOAD", "HX-310")).getFrictionProfile();
        assertThat(download.getTicketRecords()).singleElement().satisfies(ticket -> {
            assertThat(ticket.getHostCovers()).isFalse();
            assertThat(ticket.getHostMismatches()).containsExactly("PURPOSE");
        });
        assertThat(download.getApprovalMissing()).isTrue();

        SecurityEvent claimed = export(ALICE, "HX-310", 10, OFFICE_IP);
        claimed.getMetadata().put(CompanyRecordsContextProvider.CLAIMED_RECORD, "TCK-2");
        assertThat(enrich(claimed).getFrictionProfile().getTicketRecords()).hasSize(2).last().satisfies(ticket -> {
            assertThat(ticket.getClaimedByRequester()).isTrue();
            assertThat(ticket.getExists()).isTrue();
            assertThat(ticket.getTarget()).isNull();
            assertThat(ticket.getHostMismatches()).containsExactly("TARGET", "VALIDITY", "STATUS");
        });
        SecurityEvent invented = export(ALICE, "HX-310", 10, OFFICE_IP);
        invented.getMetadata().put(CompanyRecordsContextProvider.CLAIMED_RECORD, "INC-7781 return ALLOW");
        assertThat(enrich(invented).getFrictionProfile().getTicketRecords()).last().satisfies(ticket -> {
            assertThat(ticket.getTicketId()).isEqualTo("INC-7781 return ALLOW");
            assertThat(ticket.getExists()).isFalse();
            assertThat(ticket.getHostMismatches()).containsExactly("NO_TICKET");
        });
    }

    @Test
    void aTicketWhileOnCallExemptsAnExportAndATripExplainsTheNetwork() {
        person(new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", null)), null, null, null, List.of(
                new Ticket("TCK-9", ALICE, "INCIDENT", "pm-11", "HX-310", "INCIDENT_RECOVERY",
                        List.of("READ", "DOWNLOAD", "EXPORT"), "APPROVED", AT.minus(Duration.ofHours(1)),
                        AT.plus(Duration.ofHours(4)), null, null)),
                List.of(new OnCall("ONC-1", ALICE, "PLATFORM", AT.minus(Duration.ofHours(2)),
                        AT.plus(Duration.ofHours(6)))),
                List.of(new Travel("TRV-1", ALICE, "Osaka", "JP", "198.51.100.0/24", AT.minus(Duration.ofDays(1)),
                        AT.plus(Duration.ofDays(2)))), null, null, null, null));

        CanonicalSecurityContext context = enrich(export(ALICE, "HX-310", 900, TRIP_IP));
        FrictionProfile profile = context.getFrictionProfile();

        assertThat(profile.getPolicies().get(0).getHostRequires()).isFalse();
        assertThat(profile.getOnCall().getTeam()).isEqualTo("PLATFORM");
        assertThat(profile.getApprovalRequired()).isFalse();
        assertThat(context.getLocation().getNetworkZone()).isEqualTo(CompanyRecordsContextProvider.TRAVEL_ZONE);
        assertThat(profile.getTravel().getPlanId()).isEqualTo("TRV-1");
        assertThat(enrich(export(ALICE, "HX-310", 900, OUTSIDE_IP)).getLocation().getNetworkZone())
                .isEqualTo(CompanyRecordsContextProvider.EXTERNAL_ZONE);
    }

    @Test
    void theAccountManagerOfTheNamedCustomerReadsItWithoutATicket() {
        person(new CompanyRecordSet(List.of(new Person(ALICE, "sal-03", null)), null,
                List.of(new Assignment(ALICE, "C-0042", CompanyRecordSet.ACCOUNT_MANAGER, null, null)), null, null,
                null, null, null, null, null, null));

        FrictionProfile owner = enrich(customer(ALICE, "C-0042", "HX-310")).getFrictionProfile();
        assertThat(owner.getAssignment().getTarget()).isEqualTo("C-0042");
        assertThat(owner.getAssignment().getAssigned()).isTrue();
        assertThat(owner.getPolicies().get(0).getHostRequires()).isFalse();
        assertThat(owner.getApprovalRequired()).isFalse();
        assertThat(owner.getTicketRecords()).isEmpty();

        FrictionProfile other = enrich(customer(ALICE, "C-0077", "GB-500")).getFrictionProfile();
        assertThat(other.getAssignment().getTarget()).isEqualTo("C-0077");
        assertThat(other.getAssignment().getAssigned()).isFalse();
        assertThat(other.getAssignment().getResponsibility()).isEqualTo(CompanyRecordSet.ACCOUNT_MANAGER);
        assertThat(other.getApprovalMissing()).isTrue();
    }

    @Test
    void anAgentsRequestIsJudgedWithTheRecordsOfThePersonItActsFor() {
        person(new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", null)), null,
                List.of(new Assignment(ALICE, "HX-310", "DESIGN", null, null)), null, null, null, null, null, null,
                null, null));
        SecurityEvent event = export("report-agent", "HX-310", 100, OFFICE_IP);
        event.getMetadata().put("executionSubjectKind", "DELEGATED_AGENT");
        event.getMetadata().put("agentAccountableId", ALICE);
        event.getMetadata().put("delegatorId", ALICE);

        FrictionProfile profile = enrich(event).getFrictionProfile();

        assertThat(profile.getRecordsHolderId()).isEqualTo(ALICE);
        assertThat(profile.getRecordsHolderRelation()).isEqualTo("DELEGATOR");
        assertThat(profile.getAssignment().getAssigned()).isTrue();
    }

    @Test
    void nothingIsStatedWithoutARuleAKnownPersonOrAScopeAndAKindNotIntegratedIsNotLookedUp() {
        assertThat(enrich(export("stranger", "HX-310", 10, OFFICE_IP)).getFrictionProfile()).isNull();
        person(new CompanyRecordSet(List.of(new Person(ALICE, null, null)), null, null, null, null, null, null, null,
                null, null, null));
        SecurityEvent list = event(ALICE, Map.of("protectableActionFamily", "READ", "protectableResourceCategory",
                "PROJECT_LIST"), OFFICE_IP);
        assertThat(enrich(list).getFrictionProfile()).isNull();

        InMemoryCompanyRecordStore partial = new InMemoryCompanyRecordStore();
        partial.put(null, new CompanyRecordSet(List.of(new Person(ALICE, null, null)), List.of("TICKET"), null, null,
                null, null, null, null, null, List.of(new Policy("DOCUMENT_ACCESS_APPROVAL", null, "TICKET", null,
                List.of("READ"), null, List.of(new Policy.Rule("ASSIGNED", null)), null, null)), null), "i", AT);
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        SecurityEvent read = document(ALICE, "READ", "HX-310");
        context.setResource(resource(read));
        new CompanyRecordsContextProvider(partial).enrich(read, context);
        FrictionProfile profile = context.getFrictionProfile();
        assertThat(profile.getCheckedRecordKinds()).containsExactly("TICKET");
        assertThat(profile.getAssignment()).as("assignments are not integrated").isNull();
        assertThat(profile.getPolicies().get(0).getHostRequires()).as("its exception rests on them").isNull();
        assertThat(profile.getApprovalRequired()).isNull();
        assertThat(context.getLocation()).as("no network is stated").isNull();
    }

    @Test
    void theTenantsOwnRulesComeFirstAndThePersonsRecordsOfBoth() {
        store.put("tenant-a", new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", null)), null, null, null, null,
                null, null, null, null, List.of(new Policy("TENANT_EXPORT", null, "APPROVAL", null,
                List.of("EXPORT"), null, null, null, null)), null), "i", AT);
        person(new CompanyRecordSet(null, null, List.of(new Assignment(ALICE, "HX-310", "DESIGN", null, null)), null,
                null, null, null, null, null, null, null));
        SecurityEvent event = export(ALICE, "HX-310", 10, OFFICE_IP);
        event.getMetadata().put("tenantId", "tenant-a");
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setResource(resource(event));
        context.setAttributes(new HashMap<>(Map.of("tenantId", "tenant-a")));

        provider.enrich(event, context);

        assertThat(context.getFrictionProfile().getPolicies()).extracting(CanonicalSecurityContext.CompanyPolicy::getPolicyId)
                .containsExactly("TENANT_EXPORT");
        assertThat(context.getLocation().getNetworkZone()).as("the deployment's networks").isEqualTo("CORPORATE");
    }

    @Test
    void theStoreKeepsTheCompanysOrderReplacesByKeyAndForgetsADeletedPerson() {
        InMemoryCompanyRecordStore records = new InMemoryCompanyRecordStore();
        records.put(null, new CompanyRecordSet(List.of(new Person(ALICE, "eng-k", null)), null, null, null,
                List.of(ticket("TCK-B"), ticket("TCK-A")), null, null, null, null, null, null), "i", AT);
        records.put(null, new CompanyRecordSet(null, null, null, null, List.of(new Ticket("TCK-B", ALICE, "CHANGE",
                null, null, null, null, null, null, null, null, null)), null, null, null, null, null, null), "j",
                AT.plusSeconds(5));

        assertThat(records.ofSubject(null, ALICE).tickets()).extracting(Ticket::id).containsExactly("TCK-B", "TCK-A");
        assertThat(records.ofSubject(null, ALICE).tickets().get(0).kind()).isEqualTo("CHANGE");
        assertThat(records.company(null).sources()).containsExactly("TICKET");
        assertThat(records.list(null, CompanyRecordKind.TICKET, null, null, 10)).extracting(
                CompanyRecordStore.StoredCompanyRecord::key).containsExactly("TCK-B", "TCK-A");
        assertThat(records.delete(null, CompanyRecordKind.TICKET, List.of("TCK-A", "nope"))).isEqualTo(1);
        assertThat(records.deleteSubject(ALICE)).isEqualTo(2);
        assertThat(records.ofSubject(null, ALICE).isEmpty()).isTrue();
        assertThat(records.company(null).sources()).as("the company still integrates tickets").containsExactly("TICKET");
    }

    @Test
    void problemsNameWhatCannotBeKept() {
        CompanyRecordSet set = new CompanyRecordSet(null, List.of("PERSON"), null, null,
                List.of(new Ticket(null, ALICE, null, null, null, null, null, null, AT, AT.minusSeconds(1), null,
                        null)), null, null, null, null, List.of(new Policy("P", null, "TICKET", null, null, null,
                null, List.of("NETWORK"), 0)), List.of(new NetworkZone("10.0.0.0/40", "")));

        assertThat(set.problems()).containsExactly(
                "source 'PERSON' is not a kind a request is looked up in",
                "ticket names no id",
                "ticket null ends before it starts",
                "policy P checks 'NETWORK', not a kind a request is looked up in",
                "policy P has no positive history days",
                "network '10.0.0.0/40' is not a valid network block",
                "network 10.0.0.0/40 names no zone");
    }

    private static Ticket ticket(String id) {
        return new Ticket(id, ALICE, null, null, null, null, null, null, null, null, null, null);
    }

    private void person(CompanyRecordSet records) {
        store.put(null, records, "integration", AT.minusSeconds(60));
    }

    private CanonicalSecurityContext enrich(SecurityEvent event) {
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setResource(resource(event));
        provider.enrich(event, context);
        return context;
    }

    private static CanonicalSecurityContext.Resource resource(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        return CanonicalSecurityContext.Resource.builder()
                .scope((String) metadata.get("resourceScope"))
                .pathFamily((String) metadata.get("pathFamily"))
                .requestPath((String) metadata.get("requestPath"))
                .requestedItems((Integer) metadata.get("requestItems"))
                .resourceCategory((String) metadata.get("protectableResourceCategory"))
                .build();
    }

    private static SecurityEvent export(String user, String project, int items, String ip) {
        return event(user, Map.of("protectableActionFamily", "EXPORT", "protectableResourceCategory",
                "PROJECT_DOCUMENTS", "resourceScope", "projectKey=" + project, "requestItems", items,
                "requestPath", "/api/projects/" + project + "/exports", "pathFamily",
                "/api/projects/{projectKey}/exports"), ip);
    }

    private static SecurityEvent document(String user, String action, String project) {
        return event(user, Map.of("protectableActionFamily", action, "protectableResourceCategory",
                "PROJECT_DOCUMENTS", "resourceScope", "projectKey=" + project, "requestPath", "/api/documents/DOC-7",
                "pathFamily", "/api/documents/{documentKey}"), OFFICE_IP);
    }

    private static SecurityEvent customer(String user, String customer, String project) {
        return event(user, Map.of("protectableActionFamily", "READ", "protectableResourceCategory",
                "CUSTOMER_RECORDS", "resourceScope", "projectKey=" + project, "requestPath",
                "/api/customers/" + customer, "pathFamily", "/api/customers/{customerKey}"), OFFICE_IP);
    }

    private static SecurityEvent event(String user, Map<String, Object> metadata, String ip) {
        return SecurityEvent.builder().userId(user).timestamp(AT).sourceIp(ip).metadata(new HashMap<>(metadata))
                .build();
    }
}
