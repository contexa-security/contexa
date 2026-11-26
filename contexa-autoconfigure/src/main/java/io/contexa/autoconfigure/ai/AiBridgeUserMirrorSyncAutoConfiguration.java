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
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.sync.UserCopyMergeContributor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.security.ContexaUserStore;
import org.springframework.beans.factory.BeanFactory;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserEmailProvider;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;

import java.util.function.BooleanSupplier;

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

    @Bean(name = "contexaBridgeUserMirrorSyncService")
    @ConditionalOnMissingBean
    public BridgeUserMirrorSyncService bridgeUserMirrorSyncService(
            UserRepository userRepository,
            BridgeUserProfileRepository bridgeUserProfileRepository,
            BridgeProperties properties,
            @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapperProvider,
            BeanFactory beanFactory,
            ObjectProvider<BridgeUserEmailProvider> emailProvider,
            ObjectProvider<UserRolePermissionRepository> rolePermissions,
            ObjectProvider<UserCopyMergeContributor> mergeContributors) {
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                objectMapperProvider.getIfAvailable(ObjectMapper::new),
                beanFactory.containsBean("contexaCacheManager") ? beanFactory.getBean("contexaCacheManager", CacheManager.class) : null
        );
        service.setEmailProvider(emailProvider.getIfUnique());
        service.setApplicationsUsersAreContexaAccounts(applicationsUsersAreContexaAccounts(properties, beanFactory));
        service.setUserKey(ZeroTrustUserKey::of);
        service.setRolePermissions(rolePermissions.getIfAvailable());
        service.setMergeContributors(mergeContributors.orderedStream().toList());
        return service;
    }

    /**
     * Whether the application's users sign in as Contexa's own accounts (R-12, R-17): Contexa's main chain signs them in
     * (FULL), with CONTEXA_OWNED from Contexa's own store, and with HOST_OWNED from the application's store, which is
     * Contexa's own only while the application declares none. Asked when a copy is made, once the stores exist.
     */
    static BooleanSupplier applicationsUsersAreContexaAccounts(BridgeProperties properties, BeanFactory beanFactory) {
        BooleanSupplier contexasStoreSignsIn = ContexaUserStore.signsInWithContexaAccounts(beanFactory);
        return () -> {
            OperatingBehaviour behaviour = properties.operatingBehaviour();
            return behaviour.signsInTheApplicationsUsers()
                    && (!behaviour.hostComponentsWin() || contexasStoreSignsIn.getAsBoolean());
        };
    }
}
