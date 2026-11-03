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

import org.springframework.jdbc.core.JdbcOperations;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The tables whose names a Spring library writes into its own SQL (Spring Security's one-time token and passkey
 * repositories, Spring Authorization Server's services), kept under Contexa's {@code ctxa_} prefix.
 * <p>
 * The libraries take a {@link JdbcOperations} and cannot be told another table name, so the one they are given is
 * wrapped: it changes those table names in the SQL text it passes on, and nothing else. A table of the application
 * with the same standard name (an application that uses the same Spring libraries itself) is another table, in
 * another database or under another name, and is never read or written through this wrapper.
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
        return (JdbcOperations) Proxy.newProxyInstance(JdbcOperations.class.getClassLoader(),
                new Class<?>[]{JdbcOperations.class}, new Renaming(target));
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
                }
            }
            try {
                return method.invoke(target, forwarded);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }
    }
}
