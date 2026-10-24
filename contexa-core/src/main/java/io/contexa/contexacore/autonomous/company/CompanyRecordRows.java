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
import io.contexa.contexacore.autonomous.company.CompanyRecordStore.StoredCompanyRecord;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Company records as the rows a store keeps, one per record, and back (docs/agent OC-2). */
public final class CompanyRecordRows {

    /** The tenant key of the deployment's own records. */
    public static final String DEFAULT_TENANT = "";

    /** The class each kind's record is kept as; a source is kept as the kind's name. */
    public static final Map<CompanyRecordKind, Class<?>> TYPES = Map.ofEntries(
            Map.entry(CompanyRecordKind.PERSON, Person.class),
            Map.entry(CompanyRecordKind.ASSIGNMENT, Assignment.class),
            Map.entry(CompanyRecordKind.APPROVAL, Approval.class),
            Map.entry(CompanyRecordKind.TICKET, Ticket.class),
            Map.entry(CompanyRecordKind.ON_CALL, OnCall.class),
            Map.entry(CompanyRecordKind.TRAVEL, Travel.class),
            Map.entry(CompanyRecordKind.ACCESS_HISTORY, AccessDay.class),
            Map.entry(CompanyRecordKind.USAGE, Usage.class),
            Map.entry(CompanyRecordKind.POLICY, Policy.class),
            Map.entry(CompanyRecordKind.NETWORK, NetworkZone.class),
            Map.entry(CompanyRecordKind.SOURCE, String.class));

    private CompanyRecordRows() {
    }

    public static String tenant(@Nullable String tenantId) {
        return tenantId == null || tenantId.isBlank() ? DEFAULT_TENANT : tenantId.trim();
    }

    /** The rows of the records, sources first: the kinds the set integrates, then each record in the set's order. */
    public static List<StoredCompanyRecord> rows(@Nullable String tenantId, CompanyRecordSet records, String ingestedBy,
                                                 Instant ingestedAt) {
        String tenant = tenant(tenantId);
        List<StoredCompanyRecord> rows = new ArrayList<>();
        records.integratedKinds().forEach(kind -> rows.add(row(tenant, CompanyRecordKind.SOURCE, kind.name(), null,
                null, kind.name(), ingestedBy, ingestedAt)));
        records.people().forEach(person -> rows.add(row(tenant, CompanyRecordKind.PERSON, person.key(),
                person.subject(), null, person, ingestedBy, ingestedAt)));
        records.assignments().forEach(assignment -> rows.add(row(tenant, CompanyRecordKind.ASSIGNMENT,
                assignment.key(), assignment.subject(), assignment.target(), assignment, ingestedBy, ingestedAt)));
        records.approvals().forEach(approval -> rows.add(row(tenant, CompanyRecordKind.APPROVAL, approval.key(),
                approval.subject(), approval.target(), approval, ingestedBy, ingestedAt)));
        records.tickets().forEach(ticket -> rows.add(row(tenant, CompanyRecordKind.TICKET, ticket.key(),
                ticket.subject(), ticket.target(), ticket, ingestedBy, ingestedAt)));
        records.onCall().forEach(shift -> rows.add(row(tenant, CompanyRecordKind.ON_CALL, shift.key(),
                shift.subject(), null, shift, ingestedBy, ingestedAt)));
        records.travel().forEach(trip -> rows.add(row(tenant, CompanyRecordKind.TRAVEL, trip.key(), trip.subject(),
                null, trip, ingestedBy, ingestedAt)));
        records.accessDays().forEach(day -> rows.add(row(tenant, CompanyRecordKind.ACCESS_HISTORY, day.key(),
                day.subject(), day.target(), day, ingestedBy, ingestedAt)));
        records.usage().forEach(used -> rows.add(row(tenant, CompanyRecordKind.USAGE, used.key(), used.subject(),
                used.target(), used, ingestedBy, ingestedAt)));
        records.policies().forEach(policy -> rows.add(row(tenant, CompanyRecordKind.POLICY, policy.key(), null,
                null, policy, ingestedBy, ingestedAt)));
        records.networks().forEach(network -> rows.add(row(tenant, CompanyRecordKind.NETWORK, network.key(), null,
                null, network, ingestedBy, ingestedAt)));
        return rows;
    }

    /** The records the rows hold, in the rows' order. */
    public static CompanyRecordSet set(List<StoredCompanyRecord> rows) {
        List<Person> people = new ArrayList<>();
        List<String> sources = new ArrayList<>();
        List<Assignment> assignments = new ArrayList<>();
        List<Approval> approvals = new ArrayList<>();
        List<Ticket> tickets = new ArrayList<>();
        List<OnCall> onCall = new ArrayList<>();
        List<Travel> travel = new ArrayList<>();
        List<AccessDay> accessDays = new ArrayList<>();
        List<Usage> usage = new ArrayList<>();
        List<Policy> policies = new ArrayList<>();
        List<NetworkZone> networks = new ArrayList<>();
        for (StoredCompanyRecord row : rows) {
            Object record = row.record();
            switch (row.kind()) {
                case PERSON -> people.add((Person) record);
                case SOURCE -> sources.add(String.valueOf(record));
                case ASSIGNMENT -> assignments.add((Assignment) record);
                case APPROVAL -> approvals.add((Approval) record);
                case TICKET -> tickets.add((Ticket) record);
                case ON_CALL -> onCall.add((OnCall) record);
                case TRAVEL -> travel.add((Travel) record);
                case ACCESS_HISTORY -> accessDays.add((AccessDay) record);
                case USAGE -> usage.add((Usage) record);
                case POLICY -> policies.add((Policy) record);
                case NETWORK -> networks.add((NetworkZone) record);
            }
        }
        return new CompanyRecordSet(people, sources, assignments, approvals, tickets, onCall, travel, accessDays,
                usage, policies, networks);
    }

    /** Whether a kind holds a person's records rather than the company's own. */
    public static boolean personal(CompanyRecordKind kind) {
        return kind != CompanyRecordKind.POLICY && kind != CompanyRecordKind.NETWORK
                && kind != CompanyRecordKind.SOURCE;
    }

    private static StoredCompanyRecord row(String tenant, CompanyRecordKind kind, String key, @Nullable String subject,
                                           @Nullable String target, Object record, String ingestedBy,
                                           Instant ingestedAt) {
        return new StoredCompanyRecord(tenant, kind, key, subject, target, record, ingestedBy, ingestedAt);
    }
}
