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
package io.contexa.autoconfigure.compat;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Compatibility layer for the legacy property prefix scheme used by Contexa
 * up to v0.1.x. When a legacy key is detected at startup, an alias under the
 * new prefix is injected into the environment so existing application yml
 * keeps resolving without source edits.
 *
 * A single ERROR-level log line is emitted per legacy prefix detected so the
 * operator can migrate. Removal target: v0.3.0.
 */
@Slf4j
public class LegacyPrefixMigrator implements EnvironmentPostProcessor {

    /** Exact key remapping when the new key name differs from a simple prefix swap. */
    private static final Map<String, String> EXACT_KEY_MAP = new LinkedHashMap<>();

    static {
        // MFA session storage was historically split into two keys with different
        // separator conventions; both now resolve to the unified contexa key.
        EXACT_KEY_MAP.put("security.mfa.session.storage-type", "contexa.auth.mfa.session-storage-type");
    }

    /** Trailing dot is intentional - prefix matching only, never bare key. */
    private static final Map<String, String> PREFIX_MAP = new LinkedHashMap<>();

    /** Order matters: more specific prefixes must come before their roots. */
    static {
        PREFIX_MAP.put("spring.auth.", "contexa.auth.");
        PREFIX_MAP.put("security.router.", "contexa.security.router.");
        PREFIX_MAP.put("security.coldpath.", "contexa.security.coldpath.");
        PREFIX_MAP.put("security.stepup.", "contexa.security.stepup.");
        PREFIX_MAP.put("security.event.", "contexa.security.event.");
        PREFIX_MAP.put("security.kafka.", "contexa.security.kafka.");
        PREFIX_MAP.put("security.pipeline.", "contexa.security.pipeline.");
        PREFIX_MAP.put("security.plane.", "contexa.security.plane.");
        PREFIX_MAP.put("security.redis.", "contexa.security.redis.");
        PREFIX_MAP.put("security.session.", "contexa.security.session.");
        PREFIX_MAP.put("security.zerotrust.", "contexa.security.zerotrust.");
        PREFIX_MAP.put("spring.ai.security.tiered.", "contexa.security.tiered.");
        PREFIX_MAP.put("spring.ai.security.mapping.", "contexa.security.mapping.");
        PREFIX_MAP.put("spring.ai.security.", "contexa.security.tiered.llm.");
        PREFIX_MAP.put("spring.ai.vectorstore.pgvector.", "contexa.vectorstore.pgvector.");
    }

    /**
     * Reverse alias map: keys defined under the new contexa prefix that must
     * also be exposed under an external library prefix so third-party
     * autoconfigurations (Spring AI's PgVectorStoreAutoConfiguration) keep
     * receiving the same values.
     *
     * Without this, a user who migrates to contexa.vectorstore.pgvector.dimensions
     * would silently leave Spring AI's PgVectorStore bean on its default value,
     * causing dimension mismatches at query time.
     */
    private static final Map<String, String> REVERSE_PREFIX_MAP = new LinkedHashMap<>();

    static {
        REVERSE_PREFIX_MAP.put("contexa.vectorstore.pgvector.", "spring.ai.vectorstore.pgvector.");
    }

    private static final String ALIAS_SOURCE_NAME = "contexaLegacyPrefixAliases";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment env, SpringApplication app) {
        Map<String, Object> aliases = new HashMap<>();
        Map<String, Boolean> reportedPrefixes = new HashMap<>();

        for (PropertySource<?> source : env.getPropertySources()) {
            if (!(source instanceof EnumerablePropertySource<?> ePs)) {
                continue;
            }
            if (ALIAS_SOURCE_NAME.equals(source.getName())) {
                continue;
            }

            for (String name : ePs.getPropertyNames()) {
                // Exact key match (different separator / shape, can't be done by prefix alone)
                String exactNew = EXACT_KEY_MAP.get(name);
                if (exactNew != null) {
                    if (!env.containsProperty(exactNew)) {
                        aliases.putIfAbsent(exactNew, ePs.getProperty(name));
                    }
                    if (!Boolean.TRUE.equals(reportedPrefixes.get(name))) {
                        log.error("Contexa legacy property '{}' detected. Migrate to '{}'. Aliases will be removed in v0.3.0.",
                                name, exactNew);
                        reportedPrefixes.put(name, Boolean.TRUE);
                    }
                    continue;
                }

                String matched = matchLegacyPrefix(name);
                if (matched == null) {
                    continue;
                }
                String tail = name.substring(matched.length());
                String newKey = PREFIX_MAP.get(matched) + tail;
                // Operator already defined the key under the new prefix - keep their value
                if (env.containsProperty(newKey)) {
                    continue;
                }
                Object value = ePs.getProperty(name);
                aliases.putIfAbsent(newKey, value);

                if (!Boolean.TRUE.equals(reportedPrefixes.get(matched))) {
                    log.error("Contexa legacy property prefix '{}*' detected. Migrate to '{}*'. Aliases will be removed in v0.3.0.",
                            matched, PREFIX_MAP.get(matched));
                    reportedPrefixes.put(matched, Boolean.TRUE);
                }
            }
        }

        // Reverse alias: expose contexa.* keys under the external library prefix
        // so third-party autoconfigurations keep receiving values after migration.
        for (PropertySource<?> source : env.getPropertySources()) {
            if (!(source instanceof EnumerablePropertySource<?> ePs)) {
                continue;
            }
            if (ALIAS_SOURCE_NAME.equals(source.getName())) {
                continue;
            }

            for (String name : ePs.getPropertyNames()) {
                for (Map.Entry<String, String> e : REVERSE_PREFIX_MAP.entrySet()) {
                    if (!name.startsWith(e.getKey())) {
                        continue;
                    }
                    String tail = name.substring(e.getKey().length());
                    String externalKey = e.getValue() + tail;
                    if (env.containsProperty(externalKey)) {
                        break;
                    }
                    aliases.putIfAbsent(externalKey, ePs.getProperty(name));
                    break;
                }
            }
        }

        if (!aliases.isEmpty()) {
            // addLast so explicit user-defined keys (incl. command-line, env, application yml)
            // always win over our legacy-derived fallback.
            env.getPropertySources().addLast(new MapPropertySource(ALIAS_SOURCE_NAME, aliases));
        }
    }

    private static String matchLegacyPrefix(String name) {
        for (String legacy : PREFIX_MAP.keySet()) {
            if (name.startsWith(legacy)) {
                return legacy;
            }
        }
        return null;
    }
}
