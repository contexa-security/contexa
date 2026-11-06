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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The repositories of the MFA flows in Redis are made with the keyspaces of the application: the keys of the stored flows
 * are behind its name only if the distributed mode says so where it enables the repositories. The class is read as
 * metadata, since the repositories of Spring Statemachine are not on every class path.
 */
class IdentityStateMachineKeyspacesWiringTest {

    private static final String ENABLE_REDIS_REPOSITORIES =
            "org.springframework.data.redis.repository.configuration.EnableRedisRepositories";

    @Test
    @DisplayName("the distributed mode enables the state machine repositories with the keyspaces behind the application's name")
    void theRepositoriesUseTheApplicationKeyspaces() throws IOException {
        AnnotationMetadata distributed = new SimpleMetadataReaderFactory().getMetadataReader(
                IdentityStateMachineAutoConfiguration.class.getName() + "$DistributedStateMachineConfig").getAnnotationMetadata();

        Map<String, Object> enabled = distributed.getAnnotationAttributes(ENABLE_REDIS_REPOSITORIES, true);

        assertThat(enabled).isNotNull();
        assertThat(enabled.get("keyspaceConfiguration"))
                .isEqualTo("io.contexa.contexaidentity.security.statemachine.core.persist.ApplicationStateMachineKeyspaces");
    }
}
