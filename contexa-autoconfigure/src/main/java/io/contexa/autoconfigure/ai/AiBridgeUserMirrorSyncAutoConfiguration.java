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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Bridge user mirror synchronization for {@code @EnableAISecurity}.
 * <p>
 * This is an auto-configuration rather than part of {@link AiBridgeConfiguration}, because
 * {@link AiBridgeConfiguration} is imported by the {@code @EnableAISecurity} import selector and is therefore
 * evaluated before any auto-configuration, i.e. before {@link CoreDataAutoConfiguration} registers the
 * Contexa repositories this bean depends on. The bridge consumers in {@link AiBridgeConfiguration} resolve
 * this bean through {@link ObjectProvider} when they are instantiated, after all bean definitions exist.
 */
@AutoConfiguration(after = CoreDataAutoConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnBean({BridgeProperties.class, UserRepository.class, BridgeUserProfileRepository.class})
public class AiBridgeUserMirrorSyncAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public BridgeUserMirrorSyncService bridgeUserMirrorSyncService(
            UserRepository userRepository,
            BridgeUserProfileRepository bridgeUserProfileRepository,
            BridgeProperties properties,
            ObjectProvider<ObjectMapper> objectMapperProvider,
            ObjectProvider<CacheManager> cacheManagerProvider) {
        return new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                objectMapperProvider.getIfAvailable(ObjectMapper::new),
                cacheManagerProvider.getIfAvailable()
        );
    }
}
