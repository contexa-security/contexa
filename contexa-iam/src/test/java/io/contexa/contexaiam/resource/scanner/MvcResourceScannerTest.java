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
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    /** PR-49: the application's controllers were not listed until someone wrote its package into the console. */
    @Test
    @DisplayName("should scan the application's own packages beside the configured ones")
    void scansTheApplicationsOwnPackages() {
        ApplicationContext context = mock(ApplicationContext.class);
        RequestMappingHandlerMapping handlerMapping = mock(RequestMappingHandlerMapping.class);
        when(context.getBeansOfType(RequestMappingHandlerMapping.class))
                .thenReturn(Map.of("requestMappingHandlerMapping", handlerMapping));
        RequestMappingInfo mapping = RequestMappingInfo.paths("/owners/{id}")
                .options(pathPatternOptions()).methods(RequestMethod.GET).build();
        when(handlerMapping.getHandlerMethods()).thenReturn(Map.of(mapping, handler()));
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(settings.getMvcResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MvcResourceScanner scanner = new MvcResourceScanner(context, new IamAdminProperties(), settings,
                List.of("io.contexa.contexaiam.resource.scanner"));

        assertThat(scanner.scan()).singleElement()
                .satisfies(resource -> assertThat(resource.getResourceIdentifier()).isEqualTo("/owners/{id}"));
    }

    private static RequestMappingInfo.BuilderConfiguration pathPatternOptions() {
        RequestMappingInfo.BuilderConfiguration options = new RequestMappingInfo.BuilderConfiguration();
        options.setPatternParser(new PathPatternParser());
        return options;
    }

    private static HandlerMethod handler() {
        try {
            return new HandlerMethod(new ProbeController(), ProbeController.class.getMethod("owner"));
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }
    }

    @RestController
    static class ProbeController {
        public String owner() {
            return "owner";
        }
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