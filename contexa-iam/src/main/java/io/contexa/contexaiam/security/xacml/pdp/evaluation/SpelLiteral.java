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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.security.authority.RoleAuthority;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A name written into a policy expression as a SpEL string literal, and read back from one.
 * <p>
 * A role, permission or action name is text, never part of the expression. SpEL ends a single-quoted literal at a
 * quote that is not doubled, so a name written as it is can end its literal and add a condition of its own:
 * {@code X') or true or hasAuthority('Y} would make a condition that is always true. Every place that writes a name
 * into an expression goes through {@link #quote}, which doubles each quote of the name, and every place that reads a
 * name back reads the literal with {@link #PATTERN} and {@link #unquote}. A name with no quote is written exactly as
 * before, so the expressions already stored mean what they meant.
 */
public final class SpelLiteral {

    /** A single-quoted literal. Group 1 holds its body as written, quotes still doubled: pass it to {@link #unquote}. */
    public static final String PATTERN = "'((?:[^']|'')*+)'";

    private static final Pattern LITERAL = Pattern.compile(PATTERN);

    private SpelLiteral() {
    }

    /** The name as one SpEL string literal. */
    public static String quote(String value) {
        return "'" + body(value) + "'";
    }

    /** The name as a literal holds it, without the quotes around it. */
    public static String body(String value) {
        return String.valueOf(value).replace("'", "''");
    }

    /** The name a literal holds, from the body that {@link #PATTERN} captures. */
    public static String unquote(String body) {
        return body.replace("''", "'");
    }

    /** {@code hasAuthority} of exactly the given authority. */
    public static String hasAuthority(String authority) {
        return "hasAuthority(" + quote(authority) + ")";
    }

    /**
     * {@code hasAuthority} of the authority the role gives its holders, which is not always the name of the role (see
     * {@link RoleAuthority#authorityOf}). A condition that asks for a role is written with this, so that the people who
     * hold the role are the people it lets through.
     */
    public static String hasRoleAuthority(String roleName) {
        return hasAuthority(RoleAuthority.authorityOf(roleName));
    }

    /** Whether a literal of the expression holds exactly the given name, not a longer text that contains it. */
    public static boolean holds(String expression, String name) {
        if (expression == null || name == null) {
            return false;
        }
        Matcher matcher = LITERAL.matcher(expression);
        while (matcher.find()) {
            if (unquote(matcher.group(1)).equals(name)) {
                return true;
            }
        }
        return false;
    }
}
