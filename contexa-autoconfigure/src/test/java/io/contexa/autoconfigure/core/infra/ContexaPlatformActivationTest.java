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
package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class ContexaPlatformActivationTest {

    @Test
    void whatTheAnnotationPublishesActivatesThePlatform() {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        selector.selectImports(AnnotationMetadata.introspect(AnnotatedApplication.class));

        assertThat(ContexaPlatformActivation.isActive(environment)).isTrue();
    }

    /** The annotation may have stayed off, or be missing: a value in the settings says neither. */
    @Test
    void aModeInTheSettingsDoesNotActivateThePlatform() {
        assertThat(ContexaPlatformActivation.isActive(new MockEnvironment().withProperty(AiSecurityImportSelector.PROP_MODE, "SANDBOX")))
                .isFalse();
    }

    @EnableAISecurity
    static class AnnotatedApplication {
    }
}
