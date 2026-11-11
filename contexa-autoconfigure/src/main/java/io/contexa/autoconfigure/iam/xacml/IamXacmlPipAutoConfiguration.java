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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.security.xacml.pip.attribute.DatabaseAttributePIP;
import io.contexa.contexaiam.security.xacml.pip.context.DefaultContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.SubjectCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;


@Slf4j
@AutoConfiguration
public class IamXacmlPipAutoConfiguration {

    @Bean(name = "contexaDatabaseAttributePIP")
    @ConditionalOnMissingBean
    public DatabaseAttributePIP databaseAttributePIP(
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            BusinessResourceActionRepository resourceActionRepository,
            ContexaCacheService cacheService) {
        return new DatabaseAttributePIP(userRepository, auditLogRepository, resourceActionRepository, cacheService);
    }

    @Bean(name = "contexaDefaultContextHandler")
    @ConditionalOnMissingBean
    public DefaultContextHandler defaultContextHandler(
            UserRepository userRepository,
            ContexaCacheService cacheService) {
        return new DefaultContextHandler(userRepository, cacheService);
    }

    /**
     * Takes the users' cached copies out of the store once the context is ready, on a background thread so that the start
     * does not wait for it: a copy an earlier version wrote holds the password hash (PR-87). Every start does it, so the
     * last node of a rolling upgrade also takes out what the old nodes wrote until then. A store that cannot be reached
     * leaves them to their TTL.
     */
    @Bean(name = "contexaSubjectCacheClearOnStart")
    public ApplicationListener<ApplicationReadyEvent> subjectCacheClearOnStart(
            ObjectProvider<ContexaCacheService> cacheService) {
        return event -> cacheService.ifAvailable(cache -> {
            Thread clear = new Thread(() -> {
                try {
                    SubjectCache.clear(cache);
                } catch (RuntimeException e) {
                    log.error("The users' cached copies could not be cleared; they end with their TTL", e);
                }
            }, "contexa-subject-cache-clear");
            clear.setDaemon(true);
            clear.start();
        });
    }
}

