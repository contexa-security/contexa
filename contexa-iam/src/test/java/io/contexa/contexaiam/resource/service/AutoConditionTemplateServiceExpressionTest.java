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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AutoConditionTemplateServiceExpressionTest {

    @Test
    @SuppressWarnings("unchecked")
    void onlyValidAndSafeTemplatesAreSaved() {
        ConditionTemplateRepository repository = mock(ConditionTemplateRepository.class);
        when(repository.findAll()).thenReturn(List.of());
        when(repository.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
        AutoConditionTemplateService service = new AutoConditionTemplateService(
                repository, mock(ManagedResourceRepository.class), mock(AICoreOperations.class));

        List<ConditionTemplate> saved = service.saveDedupedTemplates(List.of(
                template("Business hours", "T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18"),
                template("Office network", "hasIpAddress(%s)"),
                template("Process", "T(java.lang.Runtime).getRuntime().exec('calc') != null"),
                template("Reflection", "''.getClass().forName('java.lang.Runtime') != null"),
                template("Broken", "hasRole(")));

        assertThat(saved).extracting(ConditionTemplate::getName)
                .containsExactly("Business hours", "Office network");
    }

    private ConditionTemplate template(String name, String spelTemplate) {
        return ConditionTemplate.builder().name(name).spelTemplate(spelTemplate).build();
    }
}
