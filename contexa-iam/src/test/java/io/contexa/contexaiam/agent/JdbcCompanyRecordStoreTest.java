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
package io.contexa.contexaiam.agent;

import io.contexa.contexacore.autonomous.company.CompanyRecordKind;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent OC-2: the company records kept in the Contexa database read back as they were put, in their order. */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcCompanyRecordStoreTest {

    private static final Instant NOW = Instant.parse("2026-10-23T05:00:00Z");
    private static final String SCHEMA = "company_record_test";

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private JdbcCompanyRecordStore store;

    @BeforeEach
    void setUp() throws Exception {
        Connection connection = DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        dataSource = new SingleConnectionDataSource(connection, true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        jdbc.execute("create schema " + SCHEMA);
        jdbc.execute("set search_path to " + SCHEMA);
        for (String statement : ddl()) {
            jdbc.execute(statement);
        }
        store = new JdbcCompanyRecordStore(jdbc);
    }

    @AfterEach
    void tearDown() {
        if (jdbc != null) {
            jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        }
        if (dataSource != null) {
            dataSource.destroy();
        }
    }

    @Test
    void everyKindReadsBackAsItWasPut() {
        CompanyRecordSet records = new CompanyRecordSet(List.of(new Person("alice", "eng-k", "Alice")),
                List.of("ON_CALL"),
                List.of(new Assignment("alice", "HX-310", "DESIGN", LocalDate.parse("2026-01-01"), null)),
                List.of(new Approval("APR-1", "alice", "pm-11", "HX-310", "DATA_EXPORT", List.of("EXPORT"), 500,
                        "APPROVED", NOW.minusSeconds(60), NOW.plusSeconds(3600), NOW.minusSeconds(30), true, "pm-11",
                        NOW.minusSeconds(30))),
                List.of(new Ticket("TCK-1", "alice", "CHANGE", "pm-11", "HX-310", "DESIGN_CHANGE", List.of("READ"),
                        "OPEN", NOW.minusSeconds(60), NOW.plusSeconds(60), null, null)),
                List.of(new OnCall("ONC-1", "alice", "PLATFORM", NOW.minusSeconds(60), NOW.plusSeconds(600))),
                List.of(new Travel("TRV-1", "alice", "Osaka", "JP", "198.51.100.0/24", NOW, NOW.plusSeconds(86400))),
                List.of(new AccessDay("alice", "HX-310", LocalDate.parse("2026-10-20"))),
                List.of(new Usage("job-1", "alice", "HX-310", 120, NOW.minusSeconds(10))),
                List.of(new Policy("EXPORT_APPROVAL", "An export needs an approval.", "APPROVAL", null,
                        List.of("EXPORT"), List.of("PROJECT_DOCUMENTS"), List.of(new Policy.Rule("ASSIGNED", 500)),
                        List.of("APPROVAL", "ASSIGNMENT"), 30)),
                List.of(new NetworkZone("10.40.12.0/24", "CORPORATE")));

        store.put(null, records, "hr-sync", NOW);

        CompanyRecordSet person = store.ofSubject(null, "alice");
        assertThat(person.people()).isEqualTo(records.people());
        assertThat(person.assignments()).isEqualTo(records.assignments());
        assertThat(person.approvals()).isEqualTo(records.approvals());
        assertThat(person.tickets()).isEqualTo(records.tickets());
        assertThat(person.onCall()).isEqualTo(records.onCall());
        assertThat(person.travel()).isEqualTo(records.travel());
        assertThat(person.accessDays()).isEqualTo(records.accessDays());
        assertThat(person.usage()).isEqualTo(records.usage());
        assertThat(person.policies()).isEmpty();
        CompanyRecordSet company = store.company(null);
        assertThat(company.policies()).isEqualTo(records.policies());
        assertThat(company.networks()).isEqualTo(records.networks());
        assertThat(company.sources()).containsExactlyInAnyOrder("ON_CALL", "ASSIGNMENT", "APPROVAL", "TICKET",
                "TRAVEL", "ACCESS_HISTORY");
        assertThat(store.company("tenant-b").isEmpty()).isTrue();
    }

    @Test
    void aRecordPutAgainKeepsItsPlaceAndAPersonIsForgottenWholly() {
        store.put(null, tickets("TCK-B", "TCK-A", "TCK-C"), "hr-sync", NOW);
        store.put(null, new CompanyRecordSet(null, null, null, null, List.of(new Ticket("TCK-A", "alice", "INCIDENT",
                null, null, null, null, null, null, null, null, null)), null, null, null, null, null, null), "itsm",
                NOW.plusSeconds(5));
        store.put("tenant-b", tickets("TCK-Z"), "hr-sync", NOW);

        assertThat(store.ofSubject(null, "alice").tickets()).extracting(Ticket::id)
                .containsExactly("TCK-B", "TCK-A", "TCK-C");
        assertThat(store.ofSubject(null, "alice").tickets().get(1).kind()).isEqualTo("INCIDENT");
        List<StoredCompanyRecord> listed = store.list(null, CompanyRecordKind.TICKET, "alice", null, 2);
        assertThat(listed).extracting(StoredCompanyRecord::key).containsExactly("TCK-A", "TCK-C");
        assertThat(listed.get(0).ingestedBy()).isEqualTo("itsm");
        assertThat(store.delete(null, CompanyRecordKind.TICKET, List.of("TCK-C", "TCK-X"))).isEqualTo(1);

        assertThat(store.deleteSubject("alice")).as("both tenants").isEqualTo(5);
        assertThat(store.ofSubject(null, "alice").isEmpty()).isTrue();
        assertThat(store.ofSubject("tenant-b", "alice").isEmpty()).isTrue();
        assertThat(store.company(null).sources()).as("the company still integrates tickets").containsExactly("TICKET");
    }

    private static CompanyRecordSet tickets(String... ids) {
        List<Ticket> tickets = new ArrayList<>();
        for (String id : ids) {
            tickets.add(new Ticket(id, "alice", "CHANGE", null, null, null, null, null, null, null, null, null));
        }
        return new CompanyRecordSet(List.of(new Person("alice", null, null)), null, null, null, tickets, null, null,
                null, null, null, null);
    }

    private static List<String> ddl() throws Exception {
        String schema = new ClassPathResource("db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table if not exists ctxa_company_record\\s*\\(.*?\\n\\);")
                .matcher(schema.replace("\r\n", "\n"));
        assertThat(table.find()).isTrue();
        Matcher indexes = Pattern.compile("(?is)create (?:unique )?index if not exists \\S+\\s+on ctxa_company_record\\s[^;]*;")
                .matcher(schema.replace("\r\n", "\n"));
        List<String> statements = new ArrayList<>();
        statements.add(table.group().replace(";", ""));
        while (indexes.find()) {
            statements.add(indexes.group().replace(";", ""));
        }
        assertThat(statements).hasSize(3);
        return statements;
    }
}
