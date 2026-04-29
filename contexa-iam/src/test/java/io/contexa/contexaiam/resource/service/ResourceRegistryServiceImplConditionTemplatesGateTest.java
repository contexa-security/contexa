package io.contexa.contexaiam.resource.service;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.scanner.ResourceScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("ResourceRegistryServiceImpl condition-templates enabled gate")
class ResourceRegistryServiceImplConditionTemplatesGateTest {

    private ManagedResourceRepository managedResourceRepository;
    private AutoConditionTemplateService autoConditionTemplateService;
    private PolicyRepository policyRepository;
    private IamAdminProperties iamAdminProperties;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        managedResourceRepository = mock(ManagedResourceRepository.class);
        autoConditionTemplateService = mock(AutoConditionTemplateService.class);
        policyRepository = mock(PolicyRepository.class);
        iamAdminProperties = new IamAdminProperties();

        when(managedResourceRepository.findAllWithPermission()).thenReturn(List.of());
        when(managedResourceRepository.findByStatusInWithPermission(org.mockito.ArgumentMatchers.anyList()))
                .thenReturn(List.of());
        when(policyRepository.findAllWithDetails()).thenReturn(List.of());
    }

    private ResourceRegistryServiceImpl createService() {
        @SuppressWarnings("unchecked")
        AICoreOperations<ResourceNamingContext> aiNativeProcessor = mock(AICoreOperations.class);
        return new ResourceRegistryServiceImpl(
                List.<ResourceScanner>of(),
                managedResourceRepository,
                mock(PermissionCatalogService.class),
                aiNativeProcessor,
                autoConditionTemplateService,
                policyRepository,
                iamAdminProperties,
                new StaticMessageSource());
    }

    @Test
    @DisplayName("Disabled flag must skip generateConditionTemplates() completely")
    void disabledFlag_skipsGenerateConditionTemplates() {
        iamAdminProperties.getConditionTemplates().setEnabled(false);

        createService().refreshAndSynchronizeResources();

        verify(autoConditionTemplateService, never()).generateConditionTemplates();
    }

    @Test
    @DisplayName("Enabled flag must invoke generateConditionTemplates() exactly once on startup")
    void enabledFlag_invokesGenerateConditionTemplatesOnce() {
        iamAdminProperties.getConditionTemplates().setEnabled(true);

        createService().refreshAndSynchronizeResources();

        verify(autoConditionTemplateService, times(1)).generateConditionTemplates();
    }

    @Test
    @DisplayName("Default properties (enabled=false) must not call generateConditionTemplates()")
    void defaultProperties_skipGenerateConditionTemplates() {
        createService().refreshAndSynchronizeResources();

        verify(autoConditionTemplateService, never()).generateConditionTemplates();
    }
}
