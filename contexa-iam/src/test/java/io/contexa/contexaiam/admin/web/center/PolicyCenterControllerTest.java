package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PolicyCenterController")
class PolicyCenterControllerTest {

    @Mock
    private ResourceRegistryService resourceRegistryService;

    @Mock
    private PolicyService policyService;

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private RoleService roleService;

    @Mock
    private PermissionCatalogService permissionCatalogService;

    @Mock
    private BusinessPolicyService businessPolicyService;

    @Mock
    private ConditionTemplateRepository conditionTemplateRepository;

    @Mock
    private ManagedResourceRepository managedResourceRepository;

    @InjectMocks
    private PolicyCenterController controller;

    @Nested
    @DisplayName("policyCenter")
    class PolicyCenter {

        @Test
        @DisplayName("should return policy center view with default tab")
        void defaultTab() {
            Model model = new ConcurrentModel();
            ResourceSearchCriteria criteria = new ResourceSearchCriteria();
            Pageable pageable = PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "createdAt"));

            when(resourceRegistryService.findResources(any(), any())).thenReturn(Page.empty());
            when(resourceRegistryService.getAllServiceOwners()).thenReturn(Set.of("service-a"));
            when(policyService.searchPolicies(any(), any())).thenReturn(Page.empty());

            String view = controller.policyCenter("resources", criteria, pageable, null, 0, model);

            assertThat(view).isEqualTo("admin/policy-center");
            assertThat(model.getAttribute("activePage")).isEqualTo("policy-center");
            assertThat(model.getAttribute("activeTab")).isEqualTo("resources");
            assertThat(model.getAttribute("resourcePage")).isNotNull();
            assertThat(model.getAttribute("serviceOwners")).isNotNull();
            assertThat(model.getAttribute("policy")).isNotNull();
            assertThat(model.getAttribute("policyPage")).isNotNull();
        }

        @Test
        @DisplayName("should handle exception by setting empty defaults")
        void error() {
            Model model = new ConcurrentModel();
            ResourceSearchCriteria criteria = new ResourceSearchCriteria();
            Pageable pageable = PageRequest.of(0, 10);

            when(resourceRegistryService.findResources(any(), any()))
                    .thenThrow(new RuntimeException("DB error"));

            String view = controller.policyCenter("resources", criteria, pageable, null, 0, model);

            assertThat(view).isEqualTo("admin/policy-center");
            assertThat(model.getAttribute("errorMessage")).asString().contains("Failed to load data");
            assertThat(model.getAttribute("resourcePage")).isEqualTo(Page.empty());
            assertThat(model.getAttribute("serviceOwners")).isEqualTo(Collections.emptySet());
        }
    }

    @Nested
    @DisplayName("refreshResources")
    class RefreshResources {

        @Test
        @DisplayName("should redirect with success message on refresh")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            when(policyService.getAllPolicies()).thenReturn(Collections.emptyList());
            when(managedResourceRepository.findByStatusInWithPermission(any())).thenReturn(Collections.emptyList());

            String view = controller.refreshResources(ra);

            assertThat(view).isEqualTo("redirect:/admin/policy-center?tab=resources");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("refreshed");
            verify(resourceRegistryService).refreshAndSynchronizeResources();
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new RuntimeException("Connection failed"))
                    .when(resourceRegistryService).refreshAndSynchronizeResources();

            String view = controller.refreshResources(ra);

            assertThat(view).isEqualTo("redirect:/admin/policy-center?tab=resources");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Connection failed");
        }
    }

    @Nested
    @DisplayName("createPolicyFromCenter")
    class CreatePolicyFromCenter {

        @Test
        @DisplayName("should redirect with success message on policy creation")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            PolicyDto policyDto = new PolicyDto();
            Policy created = Policy.builder().id(1L).name("TestPolicy").build();
            when(policyService.createPolicy(policyDto)).thenReturn(created);

            String view = controller.createPolicyFromCenter(policyDto, ra);

            assertThat(view).isEqualTo("redirect:/admin/policy-center?tab=list");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("created successfully");
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            PolicyDto policyDto = new PolicyDto();
            when(policyService.createPolicy(policyDto))
                    .thenThrow(new RuntimeException("Duplicate policy name"));

            String view = controller.createPolicyFromCenter(policyDto, ra);

            assertThat(view).isEqualTo("redirect:/admin/policy-center?tab=list");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Duplicate policy name");
        }
    }

    @Nested
    @DisplayName("getSystemStats")
    class GetSystemStats {

        @Test
        @DisplayName("should return stats map with all counts")
        void success() {
            when(roleService.getRoles()).thenReturn(List.of(new Role(), new Role()));
            when(permissionCatalogService.getAvailablePermissions()).thenReturn(List.of());
            when(conditionTemplateRepository.count()).thenReturn(5L);
            when(policyRepository.count()).thenReturn(10L);
            when(managedResourceRepository.count()).thenReturn(20L);
            when(managedResourceRepository.countByStatus(ManagedResource.Status.NEEDS_DEFINITION)).thenReturn(3L);
            when(managedResourceRepository.countByStatus(ManagedResource.Status.PERMISSION_CREATED)).thenReturn(7L);
            when(managedResourceRepository.countByStatus(ManagedResource.Status.POLICY_CONNECTED)).thenReturn(10L);

            ResponseEntity<Map<String, Long>> response = controller.getSystemStats();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            Map<String, Long> stats = response.getBody();
            assertThat(stats).isNotNull();
            assertThat(stats.get("roleCount")).isEqualTo(2L);
            assertThat(stats.get("permissionCount")).isEqualTo(0L);
            assertThat(stats.get("conditionCount")).isEqualTo(5L);
            assertThat(stats.get("policyCount")).isEqualTo(10L);
            assertThat(stats.get("resourceTotal")).isEqualTo(20L);
            assertThat(stats.get("resourceNeedsDefinition")).isEqualTo(3L);
            assertThat(stats.get("resourcePermissionCreated")).isEqualTo(7L);
            assertThat(stats.get("resourcePolicyConnected")).isEqualTo(10L);
        }

        @Test
        @DisplayName("should return zero counts on error")
        void error() {
            when(roleService.getRoles()).thenThrow(new RuntimeException("DB error"));

            ResponseEntity<Map<String, Long>> response = controller.getSystemStats();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            Map<String, Long> stats = response.getBody();
            assertThat(stats).isNotNull();
            assertThat(stats.get("roleCount")).isEqualTo(0L);
            assertThat(stats.get("policyCount")).isEqualTo(0L);
        }
    }

    @Nested
    @DisplayName("getPolicySummaries")
    class GetPolicySummaries {

        @Test
        @DisplayName("should return policy summaries list")
        void success() {
            Policy policy = Policy.builder()
                    .id(1L)
                    .name("TestPolicy")
                    .effect(Policy.Effect.ALLOW)
                    .build();
            when(policyService.getAllPolicies()).thenReturn(List.of(policy));

            ResponseEntity<List<PolicySummaryDto>> response = controller.getPolicySummaries();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            List<PolicySummaryDto> summaries = response.getBody();
            assertThat(summaries).isNotNull().hasSize(1);
            assertThat(summaries.get(0).getId()).isEqualTo(1L);
            assertThat(summaries.get(0).getName()).isEqualTo("TestPolicy");
            assertThat(summaries.get(0).getEffect()).isEqualTo("ALLOW");
        }

        @Test
        @DisplayName("should return empty list on error")
        void error() {
            when(policyService.getAllPolicies()).thenThrow(new RuntimeException("DB error"));

            ResponseEntity<List<PolicySummaryDto>> response = controller.getPolicySummaries();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEmpty();
        }

        @Test
        @DisplayName("should handle policy with null effect")
        void nullEffect() {
            Policy policy = Policy.builder()
                    .id(2L)
                    .name("NoEffect")
                    .effect(null)
                    .build();
            when(policyService.getAllPolicies()).thenReturn(List.of(policy));

            ResponseEntity<List<PolicySummaryDto>> response = controller.getPolicySummaries();

            List<PolicySummaryDto> summaries = response.getBody();
            assertThat(summaries).isNotNull().hasSize(1);
            assertThat(summaries.get(0).getEffect()).isEqualTo("ALLOW");
        }
    }
}
