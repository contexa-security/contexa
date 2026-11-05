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
package io.contexa.autoconfigure.iam;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurationPackages;
import org.springframework.context.support.GenericApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/** PR-49: the scan of the console's resources knows the application from Spring Boot, not from a setting. */
class ApplicationPackagesTest {

    @Test
    @DisplayName("the application's packages are the ones Spring Boot auto-configures from")
    void thePackagesSpringBootKnows() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            AutoConfigurationPackages.register(context, "org.customer.billing");
            context.refresh();

            assertThat(IamResourceAutoConfiguration.applicationPackages(context)).containsExactly("org.customer.billing");
        }
    }

    @Test
    @DisplayName("a context without them has none")
    void noneKnown() {
        try (GenericApplicationContext context = new GenericApplicationContext()) {
            context.refresh();

            assertThat(IamResourceAutoConfiguration.applicationPackages(context)).isEmpty();
        }
    }
}
