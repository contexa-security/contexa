/* Copyright 2026 The Contexa Project */
package io.contexa.contexaiam.resource.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MethodResourceScannerTest {

    @Test
    void scansProtectableMethodsFromConfiguredDatabasePackages() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"probe"});
        when(context.getBean("probe")).thenReturn(new ProbeService());
        when(settings.getResourceScannerBasePackages())
                .thenReturn(List.of("io.contexa.contexaiam.resource.scanner."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings);

        assertThat(scanner.scan()).singleElement()
                .satisfies(resource -> assertThat(resource.getResourceIdentifier()).contains("protectedOperation(String)"));
    }

    @Test
    void excludesBeansOutsideConfiguredDatabasePackages() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"probe"});
        when(context.getBean("probe")).thenReturn(new ProbeService());
        when(settings.getResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings);

        assertThat(scanner.scan()).isEmpty();
    }

    static class ProbeService {
        @Protectable
        public String protectedOperation(String value) {
            return value;
        }

        public String ordinaryOperation(String value) {
            return value;
        }
    }
}
