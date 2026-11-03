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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.ControllerAdvice;

import static org.assertj.core.api.Assertions.assertThat;

class PromptQualityRouteModelAdviceTest {

    /**
     * Ownership harness 2026-11-03: the advice put its two model attributes into every controller of the application,
     * the host's own included. It serves Contexa's screens only.
     */
    @Test
    @DisplayName("the advice reaches Contexa's controllers only")
    void reachesContexaControllersOnly() {
        ControllerAdvice advice = PromptQualityRouteModelAdvice.class.getAnnotation(ControllerAdvice.class);

        assertThat(advice).isNotNull();
        assertThat(advice.basePackages()).containsExactly("io.contexa");
    }
}
