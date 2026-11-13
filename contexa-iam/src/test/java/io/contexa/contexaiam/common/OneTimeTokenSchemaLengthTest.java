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
package io.contexa.contexaiam.common;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B-13: a one-time code is stored under the user's name, so its column holds every name Contexa's users table holds. Spring's
 * own schema gives it 50 characters, and a name of 51 to 100 (an e-mail address as the name, for one) made the code fail.
 */
class OneTimeTokenSchemaLengthTest {

    private static int lengthOf(String schema, String table, String column) {
        Matcher block = Pattern.compile("create table " + table + "\\s*\\((.*?)\\n\\);", Pattern.DOTALL).matcher(schema);
        assertThat(block.find()).as(table).isTrue();
        Matcher definition = Pattern.compile("\\b" + column + "\\s+varchar\\((\\d+)\\)").matcher(block.group(1));
        assertThat(definition.find()).as(table + "." + column).isTrue();
        return Integer.parseInt(definition.group(1));
    }

    @Test
    void aOneTimeTokenHoldsEveryUserName() throws IOException {
        String schema;
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("META-INF/contexa/db/schema.sql")) {
            assertThat(in).isNotNull();
            schema = new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("\r\n", "\n");
        }

        assertThat(lengthOf(schema, "ctxa_one_time_tokens", "username"))
                .isGreaterThanOrEqualTo(lengthOf(schema, "ctxa_users", "username"));
    }
}
