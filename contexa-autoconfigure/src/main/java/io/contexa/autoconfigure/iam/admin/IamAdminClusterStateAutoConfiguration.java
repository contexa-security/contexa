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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuQueryCache;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Keeps what each node holds in memory of the console's state the same on every node of a distributed deployment: the
 * IP access rules, the menus and the runtime settings. A change made on one node is announced on the signal the policies
 * already use ({@link PolicyReloadBroadcaster}), and every other node drops its copy or applies the stored settings
 * again. Without it a rule meant to block an address does not block it on the other nodes until they restart.
 */
@AutoConfiguration
@ConditionalOnClass(name = "org.redisson.api.RedissonClient")
@ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
public class IamAdminClusterStateAutoConfiguration {

    /**
     * Joins the console's caches to the reload signal once every bean is made: the signal is a bean of the policy
     * administration, the caches are beans of the console, and neither is made before the other.
     */
    @Bean(name = "contexaConsoleStateAcrossNodes")
    public SmartInitializingSingleton contexaConsoleStateAcrossNodes(
            ObjectProvider<PolicyReloadBroadcaster> broadcasters,
            ObjectProvider<IpAccessRuleService> ipRules,
            ObjectProvider<AdminMenuService> menus,
            ObjectProvider<AdminMenuQueryCache> menuCaches,
            ObjectProvider<SystemSettingsRuntimeApplier> runtimeSettings) {
        return () -> {
            PolicyReloadBroadcaster broadcaster = broadcasters.getIfUnique();
            if (broadcaster == null) {
                return;
            }
            ipRules.ifUnique(rules -> {
                rules.onRulesChanged(broadcaster::broadcastReload);
                broadcaster.addReloadListener(rules::refresh);
            });
            menus.ifUnique(service -> service.onMenusChanged(broadcaster::broadcastReload));
            menuCaches.ifUnique(cache -> broadcaster.addReloadListener(cache::invalidate));
            // The settings controller announces a saved setting already; the other nodes apply all of it, the zero trust
            // mode with it, where the policy reload applies the policy decision settings only.
            runtimeSettings.ifUnique(applier -> broadcaster.addReloadListener(applier::apply));
        };
    }
}
