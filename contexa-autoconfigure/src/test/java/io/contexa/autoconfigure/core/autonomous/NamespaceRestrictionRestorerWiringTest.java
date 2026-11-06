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

import io.contexa.contexacore.autonomous.service.NamespaceRestrictionRestorer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.SmartLifecycle;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;

import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The restrictions without an expiry are brought under the keys of an application's name by a bean of the distributed mode,
 * the mode that keeps them in Redis; the bean starts before the web server.
 */
class NamespaceRestrictionRestorerWiringTest {

    @Test
    @DisplayName("the distributed mode declares the restorer, and the restorer starts before Spring Boot's web server lifecycle")
    void theDistributedModeDeclaresTheRestorer() throws IOException {
        AnnotationMetadata distributed = new SimpleMetadataReaderFactory().getMetadataReader(
                CoreAutonomousAutoConfiguration.class.getName() + "$DistributedRepositoryConfiguration").getAnnotationMetadata();

        Set<MethodMetadata> beans = distributed.getAnnotatedMethods("org.springframework.context.annotation.Bean");

        assertThat(beans).anySatisfy(method -> {
            assertThat(method.getMethodName()).isEqualTo("namespaceRestrictionRestorer");
            assertThat(method.getReturnTypeName()).isEqualTo(NamespaceRestrictionRestorer.class.getName());
        });
        assertThat(distributed.getAnnotationAttributes("org.springframework.boot.autoconfigure.condition.ConditionalOnProperty"))
                .containsEntry("havingValue", "distributed");
        assertThat(SmartLifecycle.class).isAssignableFrom(NamespaceRestrictionRestorer.class);
        assertThat(NamespaceRestrictionRestorer.PHASE).isLessThan(Integer.MAX_VALUE - 2048);
    }
}
