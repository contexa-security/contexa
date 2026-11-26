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

import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Bridge v2 B5-1 (DB-1): the address of a user is unique among Contexa's own accounts only, whatever its case, so that
 * copies of applications' users may share one (two people of a legacy system with one team address no longer fail to be
 * copied) and a copy whose application shows none has none. A database of an older version has a unique constraint on the
 * address of every user and a NOT NULL column; this step moves it to the rule, in one transaction: the column takes NULL,
 * the constraints that bind the address alone are dropped, whatever they were named, and the partial unique index
 * {@value #INDEX} is made.
 * <p>
 * Contexa's own accounts that share an address apart from its case would fail the index: then nothing is changed, the
 * database keeps the old rule, and the count is reported, so an administrator gives those accounts addresses of their own.
 * A database the enterprise edition manages is moved by its migration {@code V20261126_01__user_email_scope}, not here.
 */
@Slf4j
public final class ContexaUserEmailScope {

    public enum Outcome { APPLIED, NOT_NEEDED, SHARED_ACCOUNT_ADDRESSES, NO_TABLE, FAILED }

    static final String INDEX = "ctxa_ux_users_account_email";

    private static final String SHARED_ACCOUNT_ADDRESSES = """
            select count(*) from (select lower(email) from ctxa_users
                                   where bridge_managed = false and email is not null
                                   group by lower(email) having count(*) > 1) shared""";

    private static final String ADDRESS_ONLY_UNIQUE_CONSTRAINTS = """
            select c.conname
              from pg_constraint c
              join pg_class t on t.oid = c.conrelid
              join pg_namespace n on n.oid = t.relnamespace
              join pg_attribute a on a.attrelid = t.oid and a.attnum = c.conkey[1]
             where n.nspname = current_schema() and t.relname = 'ctxa_users'
               and c.contype = 'u' and array_length(c.conkey, 1) = 1 and a.attname = 'email'""";

    private ContexaUserEmailScope() {
    }

    /** Moves the database to the rule; a database already under it, or without the table, is left as it is. */
    public static Outcome apply(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            boolean autoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                Outcome outcome = apply(connection);
                connection.commit();
                return outcome;
            } catch (SQLException | RuntimeException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(autoCommit);
            }
        } catch (SQLException | RuntimeException e) {
            log.error("[IamSeedData] The address rule of Contexa's accounts (index {}) could not be applied; the database "
                    + "keeps the rule of an older version: {}", INDEX, e.toString());
            return Outcome.FAILED;
        }
    }

    static Outcome apply(Connection connection) throws SQLException {
        if (!tableExists(connection)) {
            return Outcome.NO_TABLE;
        }
        long shared = count(connection, SHARED_ACCOUNT_ADDRESSES);
        if (shared > 0) {
            log.error("[IamSeedData] {} addresses are shared by more than one of Contexa's own accounts apart from their "
                    + "case; the address rule (index {}) is not applied until each account has an address of its own",
                    shared, INDEX);
            return Outcome.SHARED_ACCOUNT_ADDRESSES;
        }
        boolean changed = false;
        if (addressRequired(connection)) {
            execute(connection, "alter table ctxa_users alter column email drop not null");
            changed = true;
        }
        for (String constraint : addressOnlyUniqueConstraints(connection)) {
            execute(connection, "alter table ctxa_users drop constraint " + quoted(constraint));
            changed = true;
        }
        if (!indexExists(connection)) {
            execute(connection, "create unique index if not exists " + INDEX
                    + " on ctxa_users (lower(email)) where bridge_managed = false");
            changed = true;
        }
        return changed ? Outcome.APPLIED : Outcome.NOT_NEEDED;
    }

    private static boolean tableExists(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select 1 from information_schema.tables where table_schema = current_schema() and table_name = 'ctxa_users'");
             ResultSet rows = statement.executeQuery()) {
            return rows.next();
        }
    }

    private static boolean addressRequired(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select is_nullable from information_schema.columns where table_schema = current_schema() "
                        + "and table_name = 'ctxa_users' and column_name = 'email'");
             ResultSet rows = statement.executeQuery()) {
            return rows.next() && "NO".equalsIgnoreCase(rows.getString(1));
        }
    }

    private static List<String> addressOnlyUniqueConstraints(Connection connection) throws SQLException {
        List<String> names = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(ADDRESS_ONLY_UNIQUE_CONSTRAINTS);
             ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                names.add(rows.getString(1));
            }
        }
        return names;
    }

    private static boolean indexExists(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select 1 from pg_indexes where schemaname = current_schema() and indexname = ?")) {
            statement.setString(1, INDEX);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static long count(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            return rows.next() ? rows.getLong(1) : 0L;
        }
    }

    private static void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static String quoted(String identifier) {
        return "\"" + identifier.replace("\"", "\"\"") + "\"";
    }
}
