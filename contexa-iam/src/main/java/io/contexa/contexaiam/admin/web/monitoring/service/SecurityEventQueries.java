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
package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexaiam.admin.web.dashboard.DashboardHourlyStats;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The security event log's list (K138): every filter of the screen in one statement, so a user name and a subject kind
 * narrow every list: a category, a filter, and the addresses the records came from. A read answers the IDs of a page;
 * the screen reads the records of the page. The audit log keeps local times, and the moments are local times.
 */
public class SecurityEventQueries {

    public static final String AFTER_HOURS = "AFTER_HOURS";
    public static final String DISTINCT_IP = "DISTINCT_IP";
    public static final String HIGH_RISK = "HIGH_RISK";
    public static final String DECISION_ALLOW = "DECISION_ALLOW";
    public static final String DECISION_DENY = "DECISION_DENY";
    /**
     * K105: the overrides the "admin override" card counts (countAdminOverridesBetween): a refused one none, the
     * screen's period [since, until).
     */
    public static final String ADMIN_OVERRIDE_APPLIED = "ADMIN_OVERRIDE_APPLIED";
    /** K92: the decision records the dashboard's broken seals count. */
    public static final String SEAL_MISMATCH = "SEAL_MISMATCH";

    private static final String ADDRESS = "a.client_ip IS NOT NULL AND a.client_ip <> ''";

    private final Supplier<JdbcOperations> jdbc;

    public SecurityEventQueries(Supplier<JdbcOperations> jdbc) {
        this.jdbc = jdbc != null ? jdbc : () -> null;
    }

    /**
     * What the screen lists: the records written since the start; of a filter, or of the category when no filter is
     * chosen (a filter that is no other is a category); of the user names that hold the word; of a subject kind.
     *
     * @param until the end of the screen's period, the end of the overrides the card counts
     */
    public record Criteria(LocalDateTime since, LocalDateTime until, @Nullable String category, @Nullable String filter,
                           @Nullable String keyword, @Nullable String subjectKind) {
    }

    /** A page of the IDs of the records, the latest first. */
    public Page<Long> ids(Criteria criteria, Pageable pageable) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return new PageImpl<>(List.of(), pageable, 0);
        }
        List<Object> args = new ArrayList<>();
        String where = where(criteria, args);
        Long total = operations.queryForObject("SELECT COUNT(*) FROM ctxa_audit_log a" + where, Long.class,
                args.toArray());
        if (total == null || total == 0) {
            return new PageImpl<>(List.of(), pageable, 0);
        }
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<Long> ids = operations.queryForList("SELECT a.id FROM ctxa_audit_log a" + where
                + " ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?", Long.class, args.toArray());
        return new PageImpl<>(ids, pageable, total);
    }

    /**
     * A page of the addresses the records came from, the most frequent first, each as the address, how many records
     * and the latest of them; its total is how many addresses there are.
     */
    public Page<Object[]> addresses(Criteria criteria, Pageable pageable) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return new PageImpl<>(List.of(), pageable, 0);
        }
        List<Object> args = new ArrayList<>();
        String where = where(criteria, args) + " AND " + ADDRESS;
        Long total = operations.queryForObject("SELECT COUNT(DISTINCT a.client_ip) FROM ctxa_audit_log a" + where,
                Long.class, args.toArray());
        if (total == null || total == 0) {
            return new PageImpl<>(List.of(), pageable, 0);
        }
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        List<Object[]> rows = operations.query("SELECT a.client_ip, COUNT(*), MAX(a.timestamp) FROM ctxa_audit_log a"
                        + where + " GROUP BY a.client_ip ORDER BY COUNT(*) DESC, a.client_ip LIMIT ? OFFSET ?",
                (rs, row) -> new Object[]{rs.getString(1), rs.getLong(2), rs.getTimestamp(3)}, args.toArray());
        return new PageImpl<>(rows, pageable, total);
    }

    /** The records of a page of IDs in the order of the IDs; an ID whose record is gone is left out. */
    public static List<AuditLog> inOrder(List<Long> ids, Iterable<AuditLog> records) {
        Map<Long, AuditLog> byId = new HashMap<>();
        records.forEach(record -> byId.put(record.getId(), record));
        return ids.stream().map(byId::get).filter(Objects::nonNull).toList();
    }

    private static String where(Criteria criteria, List<Object> args) {
        StringBuilder where = new StringBuilder(" WHERE a.timestamp >= ?");
        args.add(Timestamp.valueOf(criteria.since()));
        String filter = text(criteria.filter());
        String category = text(criteria.category());
        if (filter != null) {
            where.append(" AND ").append(filterCondition(filter, criteria, args));
        } else if (category != null) {
            where.append(" AND a.event_category = ?");
            args.add(category);
        }
        String keyword = text(criteria.keyword());
        if (keyword != null) {
            where.append(" AND LOWER(a.principal_name) LIKE ?");
            args.add("%" + keyword.toLowerCase(Locale.ROOT) + "%");
        }
        String subjectKind = text(criteria.subjectKind());
        if (subjectKind != null) {
            where.append(" AND a.subject_kind = ?");
            args.add(subjectKind);
        }
        return where.toString();
    }

    private static String filterCondition(String filter, Criteria criteria, List<Object> args) {
        return switch (filter) {
            case AFTER_HOURS -> "(EXTRACT(HOUR FROM a.timestamp) < 9 OR EXTRACT(HOUR FROM a.timestamp) >= 18 "
                    + "OR EXTRACT(ISODOW FROM a.timestamp) IN (6, 7))";
            case DISTINCT_IP -> ADDRESS;
            case HIGH_RISK -> "a.risk_score IS NOT NULL AND a.risk_score >= 0.4";
            case DECISION_ALLOW -> "a.decision = 'ALLOW'";
            case DECISION_DENY -> "a.decision = 'DENY'";
            case "ZT_ALLOW", "ZT_BLOCK", "ZT_CHALLENGE", "ZT_ESCALATE" -> {
                args.add(filter.substring("ZT_".length()));
                yield "a.event_category = 'SECURITY_DECISION' AND a.decision = ?";
            }
            case ADMIN_OVERRIDE_APPLIED -> {
                args.add(Timestamp.valueOf(criteria.until()));
                yield "a.event_category = 'ADMIN_OVERRIDE' AND (a.outcome IS NULL OR a.outcome <> 'REFUSED') "
                        + "AND a.timestamp < ?";
            }
            case SEAL_MISMATCH -> DashboardHourlyStats.SEAL_MISMATCHED;
            default -> {
                args.add(filter);
                yield "a.event_category = ?";
            }
        };
    }

    @Nullable
    private static String text(@Nullable String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
