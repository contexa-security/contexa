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
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A migration that was written and applied before the ctxa_ prefix is never changed, so the inventory reads the tables
 * it creates under the names they have now; a table of the application with an old Contexa name in a script of its own
 * is not a Contexa table, and a name the maps do not know stays as it is.
 */
class ContexaSchemaInventoryFormerNamesTest {

    private static Resource script(String name, String sql) {
        return new ByteArrayResource(sql.getBytes(StandardCharsets.UTF_8)) {
            @Override
            public String getFilename() {
                return name;
            }
        };
    }

    @Test
    void aMigrationWrittenUnderTheFormerNamesLeadsToTheTablesUnderTheNewOnes() throws Exception {
        ContexaSchemaInventory.Snapshot inventory = ContexaSchemaInventory.fromResources("ENTERPRISE", List.of(
                script("V1__start.sql", "create table users (id bigint); create table role (id bigint);"),
                script("V2__more.sql", "create table if not exists sealed_evidence_package (id bigint); "
                        + "create table some_new_table (id bigint);")));

        assertThat(inventory.tables()).contains("ctxa_users", "ctxa_role", "ctxa_sealed_evidence_package", "some_new_table")
                .doesNotContain("users", "role", "sealed_evidence_package");
    }

    @Test
    void theOpenSourceSchemaIsAlreadyWrittenUnderTheNewNamesAndStaysSo() throws Exception {
        ContexaSchemaInventory.Snapshot inventory = ContexaSchemaInventory.fromResources("OSS",
                List.of(new ClassPathResource("db/schema.sql")));

        assertThat(inventory.tables()).contains("ctxa_users", "ctxa_sealed_evidence_package", "ctxa_schema_provenance")
                .doesNotContain("users", "sealed_evidence_package", "contexa_schema_provenance");
    }

    @Test
    void aRenameInAScriptIsStillFollowed() throws Exception {
        ContexaSchemaInventory.Snapshot inventory = ContexaSchemaInventory.fromResources("ENTERPRISE", List.of(
                script("V1__start.sql", "create table first_name (id bigint);"),
                script("V2__rename.sql", "alter table first_name rename to second_name;")));

        assertThat(inventory.tables()).contains("second_name").doesNotContain("first_name");
    }
}
