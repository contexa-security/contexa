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
package io.contexa.autoconfigure.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContexaDataSourceIsolationTest {

    @Test
    @DisplayName("Missing Contexa datasource URL should fail fast")
    void missingContexaDatasourceUrlFailsFast() {
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:h2:mem:customer");

        assertThatThrownBy(() -> ContexaDataSourceIsolation.validate(properties, environment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.datasource.url must be configured");
    }

    @Test
    @DisplayName("Dedicated Contexa datasource should be accepted")
    void dedicatedContexaDatasourceIsAccepted() {
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        properties.setUrl("jdbc:h2:mem:contexa");
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:h2:mem:customer");

        assertThatCode(() -> ContexaDataSourceIsolation.validate(properties, environment))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Shared datasource should require explicit POC approval")
    void sharedDatasourceRequiresExplicitApproval() {
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        properties.setUrl("jdbc:h2:mem:shared");
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:h2:mem:shared");

        assertThatThrownBy(() -> ContexaDataSourceIsolation.validate(properties, environment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must not share spring.datasource unless");
    }

    @Test
    @DisplayName("Shared datasource should be accepted only for an approved non-production POC")
    void sharedDatasourceIsAcceptedForApprovedNonProductionPoc() {
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        properties.setUrl("jdbc:h2:mem:shared");
        properties.getIsolation().setAllowSharedApplicationDatasource(true);
        properties.getIsolation().setSharedApplicationDatasourceRiskAccepted(true);
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:h2:mem:shared");

        assertThatCode(() -> ContexaDataSourceIsolation.validate(properties, environment))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Shared datasource should be rejected in production even with POC flags")
    void sharedDatasourceIsRejectedInProduction() {
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        properties.setUrl("jdbc:h2:mem:shared");
        properties.getIsolation().setAllowSharedApplicationDatasource(true);
        properties.getIsolation().setSharedApplicationDatasourceRiskAccepted(true);
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:h2:mem:shared");
        environment.setActiveProfiles("prod");

        assertThatThrownBy(() -> ContexaDataSourceIsolation.validate(properties, environment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.datasource must not share the application datasource in production profiles");
    }

    @Test
    @DisplayName("Shared datasource should be accepted for an explicitly marked Contexa-owned application")
    void sharedDatasourceIsAcceptedForContexaOwnedApplication() {
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        properties.setUrl("jdbc:h2:mem:contexa");
        properties.getIsolation().setContexaOwnedApplication(true);
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:h2:mem:contexa");
        environment.setActiveProfiles("prod");

        assertThatCode(() -> ContexaDataSourceIsolation.validate(properties, environment))
                .doesNotThrowAnyException();
    }
}
