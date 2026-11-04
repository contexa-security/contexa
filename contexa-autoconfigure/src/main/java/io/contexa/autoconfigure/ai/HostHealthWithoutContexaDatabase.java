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
package io.contexa.autoconfigure.ai;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.actuate.health.CompositeHealthContributor;
import org.springframework.boot.actuate.health.HealthContributor;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.NamedContributor;
import org.springframework.boot.actuate.jdbc.DataSourceHealthIndicator;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Boot's {@code db} health gathers every DataSource it finds, so Contexa's own database would decide the health of an
 * application that merely hosts Contexa, and a platform restarting on that health would restart a working application over
 * an outage of Contexa's. An application that keeps its own sign-in answers {@code /actuator/health} as it does alone.
 */
final class HostHealthWithoutContexaDatabase implements SmartInitializingSingleton {

    private static final String DATABASE_HEALTH = "db";
    private static final String CONTEXA_MEMBER = "contexaDataSource";

    private final HealthContributorRegistry registry;
    private final boolean theHostHasNoDatabase;

    HostHealthWithoutContexaDatabase(HealthContributorRegistry registry, boolean theHostHasNoDatabase) {
        this.registry = registry;
        this.theHostHasNoDatabase = theHostHasNoDatabase;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (registry == null) {
            return;
        }
        HealthContributor database = registry.getContributor(DATABASE_HEALTH);
        if (database instanceof DataSourceHealthIndicator && theHostHasNoDatabase) {
            registry.unregisterContributor(DATABASE_HEALTH);
        } else if (database instanceof CompositeHealthContributor composite) {
            withoutContexa(composite);
        }
    }

    private void withoutContexa(CompositeHealthContributor composite) {
        Map<String, HealthContributor> kept = new LinkedHashMap<>();
        for (NamedContributor<HealthContributor> member : composite) {
            if (!CONTEXA_MEMBER.equals(member.getName())) {
                kept.put(member.getName(), member.getContributor());
            }
        }
        if (composite.getContributor(CONTEXA_MEMBER) == null) {
            return;
        }
        registry.unregisterContributor(DATABASE_HEALTH);
        if (kept.size() == 1) {
            registry.registerContributor(DATABASE_HEALTH, kept.values().iterator().next());
        } else if (!kept.isEmpty()) {
            registry.registerContributor(DATABASE_HEALTH, CompositeHealthContributor.fromMap(kept));
        }
    }
}
