/* Copyright 2026 The Contexa Project */
package io.contexa.contexaiam.resource.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

import java.util.List;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
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

    @Test
    void doesNotMakeTheApplicationsBeansOutsideTheConfiguredPackages() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"hostsLazyBean"});
        doReturn(ProbeService.class).when(context).getType("hostsLazyBean", false);
        when(settings.getResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings);

        assertThat(scanner.scan()).isEmpty();
        verify(context, never()).getBean("hostsLazyBean");
    }

    /** PR-49: an application's methods were not listed until someone wrote its package into the console. */
    @Test
    void scansTheApplicationsOwnPackagesBesideTheConfiguredOnes() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"probe"});
        when(context.getBean("probe")).thenReturn(new ProbeService());
        when(settings.getResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings,
                List.of("io.contexa.contexaiam.resource.scanner"));

        assertThat(scanner.scan()).singleElement()
                .satisfies(resource -> assertThat(resource.getResourceIdentifier()).contains("protectedOperation(String)"));
    }

    @Test
    void aPackageThatOnlyStartsLikeTheApplicationsIsNotScanned() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"probe"});
        when(context.getBean("probe")).thenReturn(new ProbeService());
        when(settings.getResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings,
                List.of("io.contexa.contexaiam.resource.scan"));

        assertThat(scanner.scan()).isEmpty();
    }

    /** An application in the default package would otherwise turn the scan into a scan of every bean. */
    @Test
    void theDefaultPackageIsNoPackageToScan() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"probe"});
        when(context.getBean("probe")).thenReturn(new ProbeService());
        when(settings.getResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings, List.of(""));

        assertThat(scanner.scan()).isEmpty();
    }

    /** The application's packages are scanned now, and a refresh must still not make its lazy and prototype beans. */
    @Test
    void doesNotMakeTheApplicationsBeansInsideItsPackagesEither() {
        ApplicationContext context = mock(ApplicationContext.class);
        SystemRuntimeSettingsService settings = mock(SystemRuntimeSettingsService.class);
        when(context.getBeanDefinitionNames()).thenReturn(new String[]{"hostsLazyBean"});
        doReturn(ProbeService.class).when(context).getType("hostsLazyBean", false);
        when(settings.getResourceScannerBasePackages()).thenReturn(List.of("com.customer.other."));

        MethodResourceScanner scanner = new MethodResourceScanner(context, new ObjectMapper(), settings,
                List.of("io.contexa.contexaiam.resource.scanner"));

        assertThat(scanner.scan()).singleElement()
                .satisfies(resource -> assertThat(resource.getResourceIdentifier()).contains("protectedOperation(String)"));
        verify(context, never()).getBean("hostsLazyBean");
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
