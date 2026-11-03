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

import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * The names the tables and views of Contexa had before they got the {@code ctxa_} prefix, and the names they have now.
 * <p>
 * Migrations that were written (and applied) under the former names are never changed, so the schema inventory, which
 * reads the tables a migration chain leads to out of the scripts, reads them under their present names through this
 * map: a migration that creates {@code ctxa_prompt_governance_registry} leads to {@code ctxa_prompt_governance_registry}
 * once the migration that moves the tables to the new names has run, which every database has by the time the
 * inventory is compared with it. The maps are the {@code db/ctxa-rename-map*.tsv} resources of every Contexa module on
 * the class path (the open-source one, and the enterprise's own).
 */
final class FormerTableNames {

    private static final String PATTERN = "classpath*:db/ctxa-rename-map*.tsv";

    private static volatile Map<String, String> renamed;

    private FormerTableNames() {
    }

    /** The present name of a table or view that may still be written under its former name. */
    static String current(String name) {
        return renamed().getOrDefault(name, name);
    }

    private static Map<String, String> renamed() {
        Map<String, String> loaded = renamed;
        if (loaded == null) {
            synchronized (FormerTableNames.class) {
                loaded = renamed;
                if (loaded == null) {
                    loaded = load();
                    renamed = loaded;
                }
            }
        }
        return loaded;
    }

    private static Map<String, String> load() {
        Map<String, String> names = new HashMap<>();
        try {
            for (Resource resource : new PathMatchingResourcePatternResolver().getResources(PATTERN)) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.isBlank() || line.startsWith("#")) {
                            continue;
                        }
                        String[] columns = line.split("\t", -1);
                        if (columns.length >= 3 && Arrays.asList("table", "view").contains(columns[0])) {
                            names.put(columns[1], columns[2]);
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("The rename maps of the ctxa_ prefix could not be read: " + PATTERN, e);
        }
        return Map.copyOf(names);
    }
}
