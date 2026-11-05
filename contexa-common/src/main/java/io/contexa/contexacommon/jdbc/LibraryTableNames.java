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
package io.contexa.contexacommon.jdbc;

import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcOperations;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.Types;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The tables whose names a Spring library writes into its own SQL (Spring Security's one-time token and passkey
 * repositories, Spring Authorization Server's services), kept under Contexa's {@code ctxa_} prefix.
 * <p>
 * The libraries take a {@link JdbcOperations} and cannot be told another table name, so the one they are given is
 * wrapped: it changes those table names in the SQL text it passes on and in the questions a library asks the database
 * about its columns, and nothing else. A table of the application with the same standard name (an application that uses
 * the same Spring libraries itself) is another table, in another database or under another name, and is never read or
 * written through this wrapper.
 */
public final class LibraryTableNames {

    /** The standard name of the library's table, and the name Contexa gives it. */
    public static final Map<String, String> TABLES = Map.of(
            "one_time_tokens", "ctxa_one_time_tokens",
            "user_credentials", "ctxa_user_credentials",
            "user_entities", "ctxa_user_entities",
            "oauth2_authorization", "ctxa_oauth2_authorization",
            "oauth2_authorization_consent", "ctxa_oauth2_authorization_consent",
            "oauth2_registered_client", "ctxa_oauth2_registered_client");

    private static final Pattern NAME = Pattern.compile(
            "(?<![A-Za-z0-9_])(oauth2_authorization_consent|oauth2_registered_client|oauth2_authorization|one_time_tokens|"
                    + "user_credentials|user_entities)(?![A-Za-z0-9_])", Pattern.CASE_INSENSITIVE);

    private static final String COLUMN_TYPE = "DATA_TYPE";
    private static final Set<Integer> BYTE_COLUMN_TYPES = Set.of(Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY);

    private LibraryTableNames() {
    }

    /** The SQL with the library tables under their ctxa_ names. */
    public static String rewrite(String sql) {
        if (sql == null) {
            return null;
        }
        Matcher matcher = NAME.matcher(sql);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String old = matcher.group(1);
            String renamed = TABLES.get(old.toLowerCase(Locale.ROOT));
            matcher.appendReplacement(out, Matcher.quoteReplacement(old.equals(old.toUpperCase(Locale.ROOT))
                    ? renamed.toUpperCase(Locale.ROOT) : renamed));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    /** The operations, with the library tables renamed in every SQL text that goes through. */
    public static JdbcOperations wrap(JdbcOperations target) {
        if (target == null || Proxy.isProxyClass(target.getClass())
                && Proxy.getInvocationHandler(target) instanceof Renaming) {
            return target;
        }
        return proxy(JdbcOperations.class, new Renaming(target));
    }

    /**
     * Spring's authorization service reads the type of its columns from the database when it is built, under the
     * standard table name, and takes a column it does not find for a BLOB. Under the ctxa_ name it found none: it wrote
     * bytes into text columns, which PostgreSQL keeps in their hex form ({@code \x7b22...}), and compared them with bytes.
     */
    private static Connection renamingColumnQuestions(Connection connection) {
        return proxy(Connection.class, (proxy, method, args) -> {
            Object answer = call(connection, method, args);
            return answer instanceof DatabaseMetaData metaData ? renamingColumnQuestions(metaData) : answer;
        });
    }

    private static DatabaseMetaData renamingColumnQuestions(DatabaseMetaData metaData) {
        return proxy(DatabaseMetaData.class, (proxy, method, args) -> {
            if (!"getColumns".equals(method.getName())) {
                return call(metaData, method, args);
            }
            Object[] forwarded = args.clone();
            forwarded[2] = rewrite((String) args[2]);
            return byteColumnsAsBlobs((ResultSet) call(metaData, method, forwarded));
        });
    }

    /**
     * The service handles a column as bytes only when it is a BLOB, and PostgreSQL's bytea is BINARY to its driver: told
     * that, the service would pass the column text and read the hex form back. A table with bytea token columns (the
     * start script made them so before it was aligned with the schema, and the enterprise baseline does) keeps working.
     */
    private static ResultSet byteColumnsAsBlobs(ResultSet columns) {
        return proxy(ResultSet.class, (proxy, method, args) -> {
            Object answer = call(columns, method, args);
            boolean columnType = "getInt".equals(method.getName()) && COLUMN_TYPE.equals(args[0]);
            return columnType && BYTE_COLUMN_TYPES.contains(answer) ? Integer.valueOf(Types.BLOB) : answer;
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private static Object call(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private record Renaming(JdbcOperations target) implements InvocationHandler {

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            Object[] forwarded = args;
            if (args != null && args.length > 0) {
                if (args[0] instanceof String sql) {
                    forwarded = args.clone();
                    forwarded[0] = rewrite(sql);
                } else if (args[0] instanceof String[] statements) {
                    forwarded = args.clone();
                    String[] renamed = new String[statements.length];
                    for (int i = 0; i < statements.length; i++) {
                        renamed[i] = rewrite(statements[i]);
                    }
                    forwarded[0] = renamed;
                } else if (args[0] instanceof ConnectionCallback<?> callback) {
                    forwarded = args.clone();
                    forwarded[0] = (ConnectionCallback<Object>) connection ->
                            callback.doInConnection(renamingColumnQuestions(connection));
                }
            }
            return call(target, method, forwarded);
        }
    }
}
