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

import javax.sql.DataSource;

import org.springframework.core.env.Environment;

/**
 * Work that must reach a database of the former table names before Contexa moves it to the ctxa_ names: a module
 * whose own migrations up to some version were written against the former names finishes them here, while those names
 * still exist. Found with {@link java.util.ServiceLoader} (META-INF/services), and called only for a complete
 * installation under the former names, right before {@link ContexaSchemaPrefixMigration} renames it.
 */
public interface ContexaSchemaPrefixParticipant {

    /** Runs before the rename; a failure leaves the database as it was and stops the start. */
    void beforeRename(DataSource dataSource, Environment environment) throws Exception;
}
