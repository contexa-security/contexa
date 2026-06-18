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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogBootstrap;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.core.JdbcTemplate;

import java.lang.reflect.Method;
import java.util.Arrays;

class PqaOfficialInspectionAutoConfigurationTest {

    @Test
    @DisplayName("OSS PQA contract catalog bootstrap should run after IAM seed initialization")
    void pqaOfficialContractBootstrapDependsOnIamSeedDataInitializer() throws NoSuchMethodException {
        Method method = PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethod(
                "pqaOfficialMetricPurposeContractCatalogBootstrap",
                OfficialMetricPurposeContractCatalogWriter.class);

        assertThat(method.getReturnType()).isEqualTo(OfficialMetricPurposeContractCatalogBootstrap.class);
        assertThat(method.getAnnotation(DependsOn.class).value()).containsExactly("iamSeedDataInitializer");
        assertThat(Arrays.asList(method.getAnnotation(ConditionalOnBean.class).name()))
                .contains("iamSeedDataInitializer");
        assertThat(Arrays.asList(method.getAnnotation(ConditionalOnMissingBean.class).name()))
                .contains("officialMetricPurposeContractCatalogBootstrap",
                        "pqaOfficialMetricPurposeContractCatalogBootstrap");
    }

    @Test
    @DisplayName("OSS PQA operator snapshot service should share the bootstrapped contract writer")
    void pqaOperatorSnapshotServiceAcceptsContractCatalogWriterProvider() throws NoSuchMethodException {
        Method method = PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethod(
                "pqaOfficialVerificationOperatorSnapshotService",
                JdbcTemplate.class,
                ObjectMapper.class,
                ObjectProvider.class);

        assertThat(method.getReturnType()).isEqualTo(OfficialVerificationOperatorSnapshotService.class);
    }
}
