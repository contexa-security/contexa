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
package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class ConfiguredFactorFilterProvider {

    private final Map<FactorIdentifier, Filter> configuredFiltersByFactorId = new ConcurrentHashMap<>();

    public ConfiguredFactorFilterProvider() {
    }

    public void registerFilter(FactorIdentifier factorIdentifier, Filter filterInstance) {
        Objects.requireNonNull(factorIdentifier, "factorIdentifier cannot be null");
        Objects.requireNonNull(filterInstance, "filterInstance cannot be null");

        if (configuredFiltersByFactorId.containsKey(factorIdentifier)) {
            log.warn("Overwriting configured filter for FactorIdentifier: {}. Old: {}, New: {}",
                    factorIdentifier,
                    configuredFiltersByFactorId.get(factorIdentifier).getClass().getName(),
                    filterInstance.getClass().getName());
        }
        configuredFiltersByFactorId.put(factorIdentifier, filterInstance);
    }

    @Nullable
    public Filter getFilter(FactorIdentifier factorIdentifier) {
        Objects.requireNonNull(factorIdentifier, "factorIdentifier cannot be null");
        Filter filter = configuredFiltersByFactorId.get(factorIdentifier);
        if (filter == null) {
            log.warn("No configured filter found for FactorIdentifier: {}", factorIdentifier);
        } else {
        }
        return filter;
    }
}
