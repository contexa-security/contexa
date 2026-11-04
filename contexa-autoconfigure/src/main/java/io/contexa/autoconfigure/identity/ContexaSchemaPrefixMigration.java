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
package io.contexa.autoconfigure.identity;

import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;

import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Moves an existing Contexa database to the {@code ctxa_} names: every table, sequence, index and constraint Contexa
 * created is renamed in one transaction, so the data and the sequences' positions stay as they were, and the recorded
 * ownership of the tables follows. A database that already has the new names, or has none of the old ones, is not
 * touched.
 * <p>
 * Tables of the application are never touched, even when the application has a table with an old Contexa name
 * ({@code users}, {@code role}, {@code policy}, ...): a database counts as Contexa's only when <em>all</em> of the
 * marker tables (those Contexa's schema installation was recognised by) exist under the old names, which no
 * application has. A database that has only some of them is reported and left as it is.
 * <p>
 * The names are those of {@code db/ctxa-rename-map.tsv} (generated from the schema as it was before the prefix).
 */
@Slf4j
public final class ContexaSchemaPrefixMigration {

    public enum Outcome { NOT_NEEDED, MIGRATED, NOT_CONTEXA }

    static final String MAP = "db/ctxa-rename-map.tsv";
    static final String PREFIX = "ctxa_";
    static final int MAX_IDENTIFIER = 63;

    /** The PostgreSQL advisory lock that lets one node at a time look at, and move, the database (the bytes of "ctxapref"). */
    static final long ADVISORY_LOCK = 0x6374786170726566L;

    /** The tables Contexa's schema was recognised by, under their old names (the install-state markers before the prefix). */
    static final List<String> LEGACY_MARKERS = List.of("users", "admin_menu", "sealed_evidence_package",
            "official_metric_evaluation_contract", "official_prompt_signal_contract", "verification_run_ledger",
            "official_verification_run_batch", "official_verification_metric_snapshot", "official_metric_purpose_contract",
            "official_metric_purpose_evidence_ledger", "official_actual_prompt_problem_ledger",
            "official_verification_prompt_comparison", "pqa_sealed_evidence_resource_status",
            "ai_security_decision_observation");

    private record Entry(String kind, String oldName, String newName, String table) {
    }

    private final DataSource dataSource;
    private final List<Entry> entries;

    public ContexaSchemaPrefixMigration(DataSource dataSource) {
        this.dataSource = dataSource;
        this.entries = load();
    }

    /**
     * Moves the database when it is a complete Contexa installation under the old names. A database that cannot be
     * reached, or is not PostgreSQL, is left to the code that needs it.
     */
    public Outcome migrate() throws SQLException {
        Connection connection;
        try {
            connection = dataSource.getConnection();
        } catch (SQLException unreachable) {
            log.warn("[ContexaSchema] The database could not be reached to look for the former table names: {}",
                    unreachable.getMessage());
            return Outcome.NOT_NEEDED;
        }
        try (connection) {
            if (!"PostgreSQL".equalsIgnoreCase(connection.getMetaData().getDatabaseProductName())) {
                return Outcome.NOT_NEEDED;
            }
            boolean autoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                Outcome outcome = migrate(connection);
                connection.commit();
                return outcome;
            } catch (SQLException | RuntimeException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(autoCommit);
            }
        }
    }

    /** True when the database holds a complete Contexa installation under the old names (and none under the new). */
    public boolean hasLegacyInstallation() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            return LEGACY_MARKERS.stream().allMatch(marker -> relationExists(connection, marker));
        }
    }

    private Outcome migrate(Connection connection) throws SQLException {
        // Nodes that start together: the second waits here until the first has committed (the lock ends with the transaction),
        // and then finds the database already moved instead of renaming a table that is gone
        try (Statement lock = connection.createStatement()) {
            lock.execute("select pg_advisory_xact_lock(" + ADVISORY_LOCK + ")");
        }
        Map<String, String> tables = new LinkedHashMap<>();
        for (Entry entry : entries) {
            if (entry.kind().equals("table")) {
                tables.put(entry.oldName(), entry.newName());
            }
        }
        Set<String> legacyPresent = new LinkedHashSet<>();
        for (String old : tables.keySet()) {
            if (relationExists(connection, old)) {
                legacyPresent.add(old);
            }
        }
        if (legacyPresent.isEmpty()) {
            return Outcome.NOT_NEEDED;
        }
        List<String> missingMarkers = LEGACY_MARKERS.stream().filter(m -> !legacyPresent.contains(m)).toList();
        if (!missingMarkers.isEmpty()) {
            log.info("[ContexaSchema] Tables with Contexa's former names exist ({} of them) but not the whole installation "
                            + "(missing {}); they are taken for the application's own and left as they are",
                    legacyPresent.size(), missingMarkers);
            return Outcome.NOT_CONTEXA;
        }
        List<String> both = legacyPresent.stream().filter(old -> relationExists(connection, tables.get(old))).toList();
        if (!both.isEmpty()) {
            throw new IllegalStateException("The Contexa database has tables under both the former names and the ctxa_ names "
                    + both + "; it cannot be moved automatically. Keep one set (a backup of the former one) and start again");
        }
        int renamed = 0;
        try (Statement statement = connection.createStatement()) {
            for (String old : legacyPresent) {
                rename(statement, "table", old, tables.get(old));
                renamed++;
            }
            for (Entry entry : entries) {
                switch (entry.kind()) {
                    case "sequence" -> renameIfPresent(connection, statement, "sequence", entry.oldName(), entry.newName());
                    case "index" -> renameIfPresent(connection, statement, "index", entry.oldName(), entry.newName());
                    case "constraint" -> renameConstraint(connection, statement, entry);
                    default -> { }
                }
            }
            // what the database named itself (primary keys, unique keys, foreign keys, checks) follows the tables
            for (String table : tables.values()) {
                for (String constraint : constraintsOf(connection, table)) {
                    if (!constraint.startsWith(PREFIX)) {
                        renameConstraintOf(statement, table, constraint, fit(prefixed(constraint)));
                    }
                }
                for (String index : indexesOf(connection, table)) {
                    if (!index.startsWith(PREFIX)) {
                        rename(statement, "index", index, fit(prefixed(index)));
                    }
                }
            }
            recordedOwnershipFollows(connection, tables);
        }
        log.info("[ContexaSchema] {} tables of the Contexa database were moved to the {} names; data and sequences are unchanged",
                renamed, PREFIX);
        return Outcome.MIGRATED;
    }

    /** The recorded ownership lists the tables by name: the rows of the OSS owner name the new ones. */
    private void recordedOwnershipFollows(Connection connection, Map<String, String> tables) throws SQLException {
        if (!relationExists(connection, "ctxa_schema_inventory_object")) {
            return;
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "update ctxa_schema_inventory_object set object_name = ? "
                        + "where product_owner = 'OSS' and object_type = 'TABLE' and object_name = ?")) {
            for (Map.Entry<String, String> table : tables.entrySet()) {
                statement.setString(1, table.getValue());
                statement.setString(2, table.getKey());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private void renameIfPresent(Connection connection, Statement statement, String kind, String old, String renamed)
            throws SQLException {
        if (relationExists(connection, old) && !relationExists(connection, renamed)) {
            rename(statement, kind, old, renamed);
        }
    }

    private void rename(Statement statement, String kind, String old, String renamed) throws SQLException {
        try {
            statement.execute("alter " + kind + " " + quote(old) + " rename to " + quote(renamed));
        } catch (SQLException e) {
            throw new SQLException("The " + kind + " " + old + " could not be renamed to " + renamed + ": " + e.getMessage(),
                    e.getSQLState(), e);
        }
    }

    private void renameConstraint(Connection connection, Statement statement, Entry entry) throws SQLException {
        if (constraintExists(connection, entry.table(), entry.oldName())
                && !constraintExists(connection, entry.table(), entry.newName())) {
            renameConstraintOf(statement, entry.table(), entry.oldName(), entry.newName());
        }
    }

    private void renameConstraintOf(Statement statement, String table, String old, String renamed) throws SQLException {
        try {
            statement.execute("alter table " + quote(table) + " rename constraint " + quote(old) + " to " + quote(renamed));
        } catch (SQLException e) {
            throw new SQLException("The constraint " + old + " of " + table + " could not be renamed to " + renamed + ": "
                    + e.getMessage(), e.getSQLState(), e);
        }
    }

    private static boolean relationExists(Connection connection, String name) {
        try (PreparedStatement statement = connection.prepareStatement("select to_regclass(?) is not null")) {
            statement.setString(1, quote(name));
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("The catalog could not be read for " + name, e);
        }
    }

    private static boolean constraintExists(Connection connection, String table, String name) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select 1 from pg_constraint c where c.conname = ? and c.conrelid = to_regclass(?)")) {
            statement.setString(1, name);
            statement.setString(2, quote(table));
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static List<String> constraintsOf(Connection connection, String table) throws SQLException {
        return names(connection, "select conname from pg_constraint where conrelid = to_regclass(?) order by conname", table);
    }

    private static List<String> indexesOf(Connection connection, String table) throws SQLException {
        return names(connection, "select i.relname from pg_index x join pg_class i on i.oid = x.indexrelid "
                + "where x.indrelid = to_regclass(?) order by i.relname", table);
    }

    private static List<String> names(Connection connection, String sql, String table) throws SQLException {
        List<String> found = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, quote(table));
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    found.add(result.getString(1));
                }
            }
        }
        return found;
    }

    /** ctxa_<name>; a name that starts with contexa_ has that replaced (the tables Contexa already called contexa_...). */
    static String prefixed(String name) {
        return name.startsWith("contexa_") ? PREFIX + name.substring("contexa_".length()) : PREFIX + name;
    }

    /** The name cut to the length of an identifier, with a hash of the whole so that two cut names stay two names. */
    static String fit(String name) {
        if (name.length() <= MAX_IDENTIFIER) {
            return name;
        }
        return name.substring(0, MAX_IDENTIFIER - 9) + "_" + String.format(Locale.ROOT, "%08x", name.hashCode());
    }

    private static String quote(String identifier) {
        return '"' + identifier.replace("\"", "\"\"") + '"';
    }

    private static List<Entry> load() {
        List<Entry> loaded = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ClassPathResource(MAP, ContexaSchemaPrefixMigration.class.getClassLoader()).getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] columns = line.split("\t", -1);
                loaded.add(new Entry(columns[0], columns[1], columns[2], columns.length > 3 ? columns[3] : ""));
            }
        } catch (IOException e) {
            throw new IllegalStateException("The rename map of the ctxa_ prefix could not be read: " + MAP, e);
        }
        return List.copyOf(loaded);
    }
}
