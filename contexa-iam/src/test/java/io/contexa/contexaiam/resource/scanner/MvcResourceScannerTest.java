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
package io.contexa.contexaiam.resource.scanner;

import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import io.contexa.contexaiam.properties.IamAdminProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("MvcResourceScanner")
class MvcResourceScannerTest {

    @Test
    @DisplayName("should accept configured package prefixes")
    void acceptsConfiguredPackagePrefixes() {
        MvcResourceScanner scanner = new MvcResourceScanner(
                mock(ApplicationContext.class), new IamAdminProperties(), null);
        List<String> prefixes = SystemRuntimeSettingsService.normalizePackagePrefixes(
                "io.contexa.contexaiam.resource, io.contexa.contexaiamenterprise");

        assertThat(scanner.isConfiguredScannerPackage(MvcResourceScannerTest.class, prefixes)).isTrue();
    }

    @Test
    @DisplayName("should reject packages outside configured prefixes")
    void rejectsPackagesOutsideConfiguredPrefixes() {
        MvcResourceScanner scanner = new MvcResourceScanner(
                mock(ApplicationContext.class), new IamAdminProperties(), null);
        List<String> prefixes = SystemRuntimeSettingsService.normalizePackagePrefixes("io.contexa.contexaidentity");

        assertThat(scanner.isConfiguredScannerPackage(MvcResourceScannerTest.class, prefixes)).isFalse();
    }
}