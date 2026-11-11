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
import org.springframework.context.annotation.Bean;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The distributed mode makes the repository of the MFA flows in Redis itself and enables no Spring Data repositories in the
 * application's context: a repository factory there makes Spring Boot leave out the application's own Redis repositories.
 * The class is read as metadata, since the repositories of Spring Statemachine are not on every class path; the keys the
 * repository keeps, with the application's keyspaces, are tested on a real Redis in
 * IdentityStateMachineHostRedisRepositoriesDistributedClasspathTest.
 */
class IdentityStateMachineKeyspacesWiringTest {

    private static final String ENABLE_REDIS_REPOSITORIES =
            "org.springframework.data.redis.repository.configuration.EnableRedisRepositories";

    @Test
    @DisplayName("the distributed mode enables no Spring Data repositories and holds the repository of the flows under Contexa's name, for Contexa alone")
    void theDistributedModeEnablesNoRepositories() throws IOException {
        AnnotationMetadata distributed = new SimpleMetadataReaderFactory().getMetadataReader(
                IdentityStateMachineAutoConfiguration.class.getName() + "$DistributedStateMachineConfig").getAnnotationMetadata();

        assertThat(distributed.isAnnotated(ENABLE_REDIS_REPOSITORIES)).isFalse();

        Optional<Map<String, Object>> repository = distributed.getAnnotatedMethods(Bean.class.getName()).stream()
                .map(method -> method.getAnnotationAttributes(Bean.class.getName()))
                .filter(bean -> Arrays.asList((String[]) bean.get("name")).contains("contexaRedisStateMachineRepository"))
                .findFirst();
        assertThat(repository).isPresent();
        assertThat(repository.get().get("defaultCandidate")).isEqualTo(false);
        assertThat(distributed.getAnnotatedMethods(Bean.class.getName()).stream().map(MethodMetadata::getReturnTypeName))
                .contains("org.springframework.statemachine.data.redis.RedisStateMachineRepository");
    }
}
