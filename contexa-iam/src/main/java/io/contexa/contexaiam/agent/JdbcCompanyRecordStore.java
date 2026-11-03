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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.contexacore.autonomous.company.CompanyRecordKind;
import io.contexa.contexacore.autonomous.company.CompanyRecordRows;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The company records kept in the {@code ctxa_company_record} table (docs/agent OC-2): one row per record, its body as
 * JSON. Putting a record again replaces its body and keeps its place ({@code record_seq}), so records keep the order in
 * which the company first gave them.
 */
public class JdbcCompanyRecordStore implements CompanyRecordStore {

    private static final String COLUMNS = "tenant_key, record_kind, record_key, subject_id, target_key, body, "
            + "ingested_by, ingested_at";

    private final JdbcOperations jdbc;
    private final ObjectMapper json;

    public JdbcCompanyRecordStore(JdbcOperations jdbc) {
        if (jdbc == null) {
            throw new IllegalArgumentException("A JDBC connection is required");
        }
        this.jdbc = jdbc;
        this.json = new ObjectMapper().findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    @Override
    public void put(@Nullable String tenantId, CompanyRecordSet records, String ingestedBy, Instant ingestedAt) {
        List<Object[]> rows = new ArrayList<>();
        for (StoredCompanyRecord row : CompanyRecordRows.rows(tenantId, records, ingestedBy, ingestedAt)) {
            rows.add(new Object[]{row.tenantId(), row.kind().name(), row.key(), row.subject(), row.target(),
                    write(row.record()), row.ingestedBy(), Timestamp.from(row.ingestedAt())});
        }
        if (rows.isEmpty()) {
            return;
        }
        jdbc.batchUpdate("insert into ctxa_company_record (" + COLUMNS + ") values (?, ?, ?, ?, ?, ?, ?, ?) "
                + "on conflict (tenant_key, record_kind, record_key) do update set subject_id = excluded.subject_id, "
                + "target_key = excluded.target_key, body = excluded.body, ingested_by = excluded.ingested_by, "
                + "ingested_at = excluded.ingested_at", rows);
    }

    @Override
    public int delete(@Nullable String tenantId, CompanyRecordKind kind, Collection<String> keys) {
        int removed = 0;
        for (String key : keys) {
            if (key != null) {
                removed += jdbc.update("delete from ctxa_company_record where tenant_key = ? and record_kind = ? "
                        + "and record_key = ?", CompanyRecordRows.tenant(tenantId), kind.name(), key);
            }
        }
        return removed;
    }

    @Override
    public CompanyRecordSet ofSubject(@Nullable String tenantId, String subject) {
        if (subject == null) {
            return CompanyRecordSet.EMPTY;
        }
        return CompanyRecordRows.set(jdbc.query("select " + COLUMNS + " from ctxa_company_record where subject_id = ? "
                        + "and tenant_key = ? and record_kind not in ('POLICY', 'NETWORK', 'SOURCE') "
                        + "order by record_seq", this::row, subject, CompanyRecordRows.tenant(tenantId)));
    }

    @Override
    public CompanyRecordSet company(@Nullable String tenantId) {
        return CompanyRecordRows.set(jdbc.query("select " + COLUMNS + " from ctxa_company_record where tenant_key = ? "
                + "and record_kind in ('POLICY', 'NETWORK', 'SOURCE') order by record_seq", this::row,
                CompanyRecordRows.tenant(tenantId)));
    }

    @Override
    public List<StoredCompanyRecord> list(@Nullable String tenantId, @Nullable CompanyRecordKind kind,
                                          @Nullable String subject, @Nullable String target, int limit) {
        StringBuilder sql = new StringBuilder("select " + COLUMNS + " from ctxa_company_record where tenant_key = ?");
        List<Object> arguments = new ArrayList<>();
        arguments.add(CompanyRecordRows.tenant(tenantId));
        if (kind != null) {
            sql.append(" and record_kind = ?");
            arguments.add(kind.name());
        }
        if (subject != null) {
            sql.append(" and subject_id = ?");
            arguments.add(subject);
        }
        if (target != null) {
            sql.append(" and target_key = ?");
            arguments.add(target);
        }
        sql.append(" order by ingested_at desc, record_seq desc limit ?");
        arguments.add(Math.max(limit, 0));
        return jdbc.query(sql.toString(), this::row, arguments.toArray());
    }

    @Override
    public int deleteSubject(String subject) {
        if (subject == null) {
            return 0;
        }
        return jdbc.update("delete from ctxa_company_record where subject_id = ? "
                + "and record_kind not in ('POLICY', 'NETWORK', 'SOURCE')", subject);
    }

    private StoredCompanyRecord row(ResultSet rs, int rowNumber) throws SQLException {
        CompanyRecordKind kind = CompanyRecordKind.valueOf(rs.getString("record_kind"));
        Object record;
        try {
            record = json.readValue(rs.getString("body"), CompanyRecordRows.TYPES.get(kind));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("A company record could not be read: " + kind + " "
                    + rs.getString("record_key"), e);
        }
        return new StoredCompanyRecord(rs.getString("tenant_key"), kind, rs.getString("record_key"),
                rs.getString("subject_id"), rs.getString("target_key"), record, rs.getString("ingested_by"),
                rs.getTimestamp("ingested_at").toInstant());
    }

    private String write(Object record) {
        try {
            return json.writeValueAsString(record);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("A company record could not be written", e);
        }
    }
}
