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

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RC PR-44. Whichever of the two scripts creates a table first decides its columns for the life of the database, so the
 * scripts must describe the same columns: a database must not depend on which bean started first.
 */
class OAuth2SchemaScriptsTest {

    private static final String START_SCRIPT = "contexa-oauth2-authorization-schema.sql";
    private static final String CANONICAL_SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final Pattern COLUMN = Pattern.compile("^(\\w+)\\s+(\\w+(?:\\(\\d+\\))?)");

    @Test
    void bothScriptsDescribeTheSameColumns() throws IOException {
        for (String table : List.of("ctxa_oauth2_authorization", "ctxa_oauth2_registered_client", "ctxa_oauth2_authorization_consent")) {
            assertThat(columns(START_SCRIPT, table)).as(table).isNotEmpty().isEqualTo(columns(CANONICAL_SCHEMA, table));
        }
    }

    /** The columns of a create table statement, by name; constraints written as lines of their own are not columns. */
    private static Map<String, String> columns(String script, String table) throws IOException {
        String sql = new ClassPathResource(script).getContentAsString(StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        Matcher statement = Pattern.compile("create table (?:if not exists )?" + table + "\\s*\\((.*?)\\n\\s*\\);", Pattern.DOTALL).matcher(sql);
        assertThat(statement.find()).as(table + " in " + script).isTrue();
        Map<String, String> columns = new LinkedHashMap<>();
        for (String line : statement.group(1).split("\\R")) {
            Matcher column = COLUMN.matcher(line.trim());
            if (column.find() && !List.of("primary", "foreign", "unique", "constraint", "references").contains(column.group(1))) {
                columns.put(column.group(1), column.group(2));
            }
        }
        return columns;
    }
}
