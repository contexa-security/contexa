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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.RestrictionRestorer;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The blocks the database holds in force are written again by a bean that every infrastructure mode has, the standalone
 * mode that keeps them in memory as much as the distributed mode that keeps them in Redis; the bean starts before the web
 * server.
 */
class RestrictionRestorerWiringTest {

    private static final String BEAN = "org.springframework.context.annotation.Bean";
    private static final String ON_PROPERTY = "org.springframework.boot.autoconfigure.condition.ConditionalOnProperty";

    @Test
    @DisplayName("the restorer is declared for every infrastructure mode, not by the distributed one, and starts before Spring Boot's web server lifecycle")
    void everyModeDeclaresTheRestorer() throws IOException {
        SimpleMetadataReaderFactory readers = new SimpleMetadataReaderFactory();
        AnnotationMetadata autoConfiguration =
                readers.getMetadataReader(CoreAutonomousAutoConfiguration.class.getName()).getAnnotationMetadata();
        AnnotationMetadata distributed = readers.getMetadataReader(
                CoreAutonomousAutoConfiguration.class.getName() + "$DistributedRepositoryConfiguration").getAnnotationMetadata();

        Set<MethodMetadata> beans = autoConfiguration.getAnnotatedMethods(BEAN);

        assertThat(beans).filteredOn(method -> method.getMethodName().equals("restrictionRestorer"))
                .singleElement().satisfies(method -> {
                    assertThat(method.getReturnTypeName()).isEqualTo(RestrictionRestorer.class.getName());
                    assertThat(method.isAnnotated(ON_PROPERTY)).as("no infrastructure mode is asked for").isFalse();
                });
        assertThat(distributed.getAnnotatedMethods(BEAN)).extracting(MethodMetadata::getReturnTypeName)
                .doesNotContain(RestrictionRestorer.class.getName());
        assertThat(SmartLifecycle.class).isAssignableFrom(RestrictionRestorer.class);
        assertThat(RestrictionRestorer.PHASE).isLessThan(Integer.MAX_VALUE - 2048);
    }

    @Test
    @DisplayName("the bean of a standalone application writes again the blocks the record holds in force into the memory store")
    void theStandaloneBeanWritesTheBlocksIntoMemory() {
        InMemoryZeroTrustActionRepository memory = new InMemoryZeroTrustActionRepository(0);
        IBlockedUserRecorder record = new IBlockedUserRecorder() {
            @Override
            public void recordBlock(String requestId, String userId, String username, String action, String reasoning,
                                    String sourceIp, String userAgent) {
            }

            @Override
            public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
            }

            @Override
            public List<String> blocksInForce() {
                return List.of("alice");
            }
        };
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("actions", memory);
        beans.addBean("record", record);
        beans.addBean("context", new InMemorySecurityContextDataStore());

        RestrictionRestorer restorer = new CoreAutonomousAutoConfiguration().restrictionRestorer(
                beans.getBeanProvider(ZeroTrustActionRepository.class), beans.getBeanProvider(IBlockedUserRecorder.class),
                beans.getBeanProvider(SecurityContextDataStore.class));
        restorer.start();
        restorer.stop();

        assertThat(memory.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
    }
}
