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
package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyAvailablePermissionsResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyApiResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyBatchCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyCleanupResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyErrorResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMigrationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyPageResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyPermissionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyQuickCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyResourceResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRollbackRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRoleResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySpelPermissionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySystemStatsResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionDiffResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSnapshotResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos;
import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.SecuritySpel;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.SecuritySpelRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

    @Mock
    private SecuritySpelRepository securitySpelRepository;

    @Mock
    private MessageSource messageSource;

    @Mock
    private PolicyValidationService policyValidationService;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private PolicyVersionService policyVersionService;

    @Mock
    private PolicyMatrixService policyMatrixService;

    @Mock
    private PolicyCombiningProperties policyCombiningProperties;

    @Mock
    private PolicyEnrichmentService policyEnrichmentService;

    @Mock
    private CustomDynamicAuthorizationManager authorizationManager;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    private PolicyCenterController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(policyCombiningProperties.getCombiningAlgorithm())
                .thenReturn(CombiningAlgorithm.DENY_OVERRIDES);
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> {
                    String key = inv.getArgument(0);
                    Object[] args = inv.getArgument(1);
                    if (args != null && args.length > 0) {
                        return key + " " + Arrays.stream(args)
                                .map(String::valueOf).collect(Collectors.joining(" "));
                    }
                    return key;
                });
        PolicyCenterQueryService policyCenterQueryService = new PolicyCenterQueryService(
                resourceRegistryService,
                roleService,
                permissionCatalogService,
                conditionTemplateRepository,
                managedResourceRepository,
                securitySpelRepository,
                policyRepository,
                policyService,
                policyVersionService
        );
        PolicyCenterCommandService policyCenterCommandService = new PolicyCenterCommandService(
                resourceRegistryService,
                policyService,
                policyRepository,
                roleService,
                businessPolicyService,
                managedResourceRepository,
                permissionRepository,
                policyValidationService,
                policyEnrichmentService,
                policyVersionService,
                authorizationManager,
                centralAuditFacade,
                messageSource
        );
        PolicyCenterPageService policyCenterPageService = new PolicyCenterPageService(
                resourceRegistryService,
                policyService,
                policyCombiningProperties
        );
        PolicyCenterAnalysisService policyCenterAnalysisService = new PolicyCenterAnalysisService(
                policyService,
                policyValidationService,
                permissionRepository,
                policyMatrixService
        );
        controller = new PolicyCenterController(
                messageSource,
                policyCenterPageService,
                policyCenterQueryService,
                policyCenterCommandService,
                policyCenterAnalysisService
        );
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .build();
    }

    @Nested
    @DisplayName("controller DTO boundary")
    class ControllerDtoBoundary {

        @Test
        @DisplayName("public controller signatures do not expose domain or PAP DTO types")
        void publicControllerSignaturesDoNotExposeDomainOrPapDtos() {
            Set<String> forbiddenTypeNames = Set.of(
                    "io.contexa.contexaiam.domain.dto.PolicyDto",
                    "io.contexa.contexaiam.domain.dto.ResourceSearchCriteria",
                    "io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport",
                    "io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport",
                    "io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport",
                    "io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport",
                    "io.contexa.contexaiam.security.xacml.pap.dto.SimulationRequest",
                    "io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport",
                    "io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport"
            );

            for (Method method : PolicyCenterController.class.getDeclaredMethods()) {
                if (!Modifier.isPublic(method.getModifiers())) {
                    continue;
                }
                assertNoForbiddenType(method.getGenericReturnType(), forbiddenTypeNames, method.toGenericString());
                for (Type parameterType : method.getGenericParameterTypes()) {
                    assertNoForbiddenType(parameterType, forbiddenTypeNames, method.toGenericString());
                }
            }
        }

        @Test
        @DisplayName("public response DTO components do not expose wildcard Object or PAP DTO types")
        void publicResponseDtoComponentsAreFullyTyped() {
            Set<String> forbiddenTypeNames = Set.of(
                    "?",
                    "java.lang.Object",
                    "io.contexa.contexaiam.security.xacml.pap.dto."
            );

            Arrays.stream(PolicyCenterDtos.class.getDeclaredClasses())
                    .filter(type -> type.getSimpleName().startsWith("Policy"))
                    .filter(type -> type.getSimpleName().endsWith("Response"))
                    .filter(Class::isRecord)
                    .forEach(responseType -> Arrays.stream(responseType.getRecordComponents())
                            .forEach(component -> assertNoForbiddenType(
                                    component.getGenericType(),
                                    forbiddenTypeNames,
                                    responseType.getSimpleName() + "." + component.getName())));
        }

        private void assertNoForbiddenType(Type type, Set<String> forbiddenTypeNames, String context) {
            String typeName = type.getTypeName();
            forbiddenTypeNames.forEach(forbidden ->
                    assertThat(typeName)
                            .as(context)
                            .doesNotContain(forbidden));
        }
    }

    @Nested
    @DisplayName("lookup APIs")
    class LookupApis {

        @Test
        @DisplayName("searchRoles returns typed page DTO with existing JSON fields")
        void searchRoles() {
            Role role = Role.builder()
                    .id(10L)
                    .roleName("ADMIN")
                    .roleDesc("Admin role")
                    .build();
            Pageable pageable = PageRequest.of(0, 20);
            when(roleService.searchRoles("adm", pageable))
                    .thenReturn(new PageImpl<>(List.of(role), pageable, 1));

            ResponseEntity<PolicyPageResponse<PolicyRoleResponse>> response =
                    controller.searchRoles("adm", pageable);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            PolicyPageResponse<PolicyRoleResponse> body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.content()).hasSize(1);
            assertThat(body.totalElements()).isEqualTo(1L);
            assertThat(body.totalPages()).isEqualTo(1);
            assertThat(body.number()).isEqualTo(0);
            assertThat(body.size()).isEqualTo(20);
            assertThat(body.content().get(0).id()).isEqualTo(10L);
            assertThat(body.content().get(0).roleName()).isEqualTo("ADMIN");
            assertThat(body.content().get(0).roleDesc()).isEqualTo("Admin role");
            assertThat(body.content().get(0).expression()).isFalse();
            assertThat(body.content().get(0).enabled()).isFalse();
            assertThat(body.content().get(0).permissionCount()).isZero();
        }

        @Test
        @DisplayName("getAvailablePermissions returns typed page DTO and role mapping metadata")
        void getAvailablePermissions() {
            Permission mappedPermission = Permission.builder().id(100L).name("READ").build();
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            role.getRolePermissions().add(RolePermission.builder()
                    .role(role)
                    .permission(mappedPermission)
                    .build());
            PermissionDto permission = PermissionDto.builder()
                    .id(101L)
                    .name("WRITE")
                    .friendlyName("Write")
                    .description("Write permission")
                    .targetType("CRUD")
                    .actionType("WRITE")
                    .conditionExpression("true")
                    .linkedResourceId(1L)
                    .linkedResourceIdentifier("/api/orders")
                    .build();
            Pageable pageable = PageRequest.of(0, 20);
            when(roleService.getRole(10L)).thenReturn(role);
            when(permissionCatalogService.searchAvailablePermissions(eq("wri"), eq(Collections.emptySet()), eq(pageable)))
                    .thenReturn(new PageImpl<>(List.of(permission), pageable, 1));

            ResponseEntity<PolicyAvailablePermissionsResponse> response =
                    controller.getAvailablePermissions(List.of(10L), "wri", pageable);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            PolicyAvailablePermissionsResponse body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.content()).hasSize(1);
            PolicyPermissionResponse item = body.content().get(0);
            assertThat(item.id()).isEqualTo(101L);
            assertThat(item.name()).isEqualTo("WRITE");
            assertThat(item.friendlyName()).isEqualTo("Write");
            assertThat(item.linkedResourceIdentifier()).isEqualTo("/api/orders");
            assertThat(body.alreadyMappedIds()).containsExactly(100L);
            assertThat(body.rolePermissionMap()).containsEntry("10", List.of(100L));
        }

        @Test
        @DisplayName("searchResourcesApi returns typed resource page with string enum values")
        void searchResourcesApi() {
            LocalDateTime createdAt = LocalDateTime.of(2026, 4, 21, 9, 30);
            ManagedResource resource = ManagedResource.builder()
                    .id(1L)
                    .resourceIdentifier("/api/orders")
                    .resourceType(ManagedResource.ResourceType.URL)
                    .httpMethod(ManagedResource.HttpMethod.GET)
                    .friendlyName("Orders")
                    .status(ManagedResource.Status.NEEDS_DEFINITION)
                    .serviceOwner("billing")
                    .sourceCodeLocation("OrderController.java")
                    .apiDocsUrl("https://docs.example/orders")
                    .description("Orders API")
                    .createdAt(createdAt)
                    .build();
            Pageable pageable = PageRequest.of(0, 20, Sort.by(Sort.Direction.DESC, "createdAt"));
            PolicyResourceSearchRequest criteria = new PolicyResourceSearchRequest();
            when(resourceRegistryService.findResources(any(ResourceSearchCriteria.class), eq(pageable)))
                    .thenReturn(new PageImpl<>(List.of(resource), pageable, 1));

            ResponseEntity<PolicyPageResponse<PolicyResourceResponse>> response =
                    controller.searchResourcesApi(criteria, pageable);

            PolicyPageResponse<PolicyResourceResponse> body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.content()).hasSize(1);
            PolicyResourceResponse item = body.content().get(0);
            assertThat(item.id()).isEqualTo(1L);
            assertThat(item.resourceIdentifier()).isEqualTo("/api/orders");
            assertThat(item.resourceType()).isEqualTo("URL");
            assertThat(item.httpMethod()).isEqualTo("GET");
            assertThat(item.status()).isEqualTo("NEEDS_DEFINITION");
            assertThat(item.createdAt()).isEqualTo("2026-04-21T09:30");
        }

        @Test
        @DisplayName("searchResourcesApi rejects invalid enum filters without server error")
        void searchResourcesApiInvalidEnum() throws Exception {
            mockMvc.perform(get("/contexa/admin/policy-center/api/resources")
                            .param("resourceType", "not-a-type"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.content").isArray())
                    .andExpect(jsonPath("$.totalElements").value(0))
                    .andExpect(jsonPath("$.totalPages").value(0));

            verify(resourceRegistryService, never()).findResources(any(), any());
        }

        @Test
        @DisplayName("getSpelPermissions returns typed list DTO")
        void getSpelPermissions() {
            SecuritySpel spel = SecuritySpel.builder()
                    .id(1L)
                    .name("Owner Only")
                    .expression("principal == owner")
                    .description("Owner can access")
                    .category("ownership")
                    .build();
            when(securitySpelRepository.search("%owner%")).thenReturn(List.of(spel));

            ResponseEntity<List<PolicySpelPermissionResponse>> response =
                    controller.getSpelPermissions("owner");

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsExactly(new PolicySpelPermissionResponse(
                    1L,
                    "Owner Only",
                    "principal == owner",
                    "Owner can access",
                    "ownership"
            ));
        }
    }

    @Nested
    @DisplayName("policyCenter")
    class PolicyCenter {

        @Test
        @DisplayName("should return policy center view with default tab")
        void defaultTab() {
            Model model = new ConcurrentModel();
            PolicyResourceSearchRequest criteria = new PolicyResourceSearchRequest();
            Pageable pageable = PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "createdAt"));

            when(resourceRegistryService.findResources(any(), any())).thenReturn(Page.empty());
            when(resourceRegistryService.getAllServiceOwners()).thenReturn(Set.of("service-a"));
            when(policyService.searchPolicies(any(), any(), any(), any())).thenReturn(Page.empty());

            String view = controller.policyCenter("resources", criteria, pageable, null, null, null, 0, model);

            assertThat(view).isEqualTo("contexa/admin/policy-center");
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
            PolicyResourceSearchRequest criteria = new PolicyResourceSearchRequest();
            Pageable pageable = PageRequest.of(0, 10);

            when(resourceRegistryService.findResources(any(), any()))
                    .thenThrow(new RuntimeException("DB error"));

            String view = controller.policyCenter("resources", criteria, pageable, null, null, null, 0, model);

            assertThat(view).isEqualTo("contexa/admin/policy-center");
            assertThat(model.getAttribute("errorMessage")).asString().contains("msg.policy.load.error");
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

            assertThat(view).isEqualTo("redirect:/contexa/admin/policy-center?tab=resources");
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

            assertThat(view).isEqualTo("redirect:/contexa/admin/policy-center?tab=resources");
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
            PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
            Policy created = Policy.builder().id(1L).name("TestPolicy").build();
            when(policyService.createPolicy(any(PolicyDto.class))).thenReturn(created);

            String view = controller.createPolicyFromCenter(request, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/policy-center?tab=list");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("msg.policy.created");
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
            when(policyService.createPolicy(any(PolicyDto.class)))
                    .thenThrow(new RuntimeException("Duplicate policy name"));

            String view = controller.createPolicyFromCenter(request, ra);

            assertThat(view).isEqualTo("redirect:/contexa/admin/policy-center?tab=list");
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

            ResponseEntity<PolicySystemStatsResponse> response = controller.getSystemStats();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            PolicySystemStatsResponse stats = response.getBody();
            assertThat(stats).isNotNull();
            assertThat(stats.roleCount()).isEqualTo(2L);
            assertThat(stats.permissionCount()).isEqualTo(0L);
            assertThat(stats.conditionCount()).isEqualTo(5L);
            assertThat(stats.policyCount()).isEqualTo(10L);
            assertThat(stats.resourceTotal()).isEqualTo(20L);
            assertThat(stats.resourceNeedsDefinition()).isEqualTo(3L);
            assertThat(stats.resourcePermissionCreated()).isEqualTo(7L);
            assertThat(stats.resourcePolicyConnected()).isEqualTo(10L);
        }

        @Test
        @DisplayName("should return zero counts on error")
        void error() {
            when(roleService.getRoles()).thenThrow(new RuntimeException("DB error"));

            ResponseEntity<PolicySystemStatsResponse> response = controller.getSystemStats();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            PolicySystemStatsResponse stats = response.getBody();
            assertThat(stats).isNotNull();
            assertThat(stats.roleCount()).isEqualTo(0L);
            assertThat(stats.permissionCount()).isEqualTo(0L);
            assertThat(stats.conditionCount()).isEqualTo(0L);
            assertThat(stats.policyCount()).isEqualTo(0L);
            assertThat(stats.resourceTotal()).isNull();
            assertThat(stats.resourceNeedsDefinition()).isNull();
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

    @Nested
    @DisplayName("typed command APIs")
    class TypedCommandApis {

        @Test
        @DisplayName("quickCreatePolicy returns typed success response with existing fields")
        void quickCreatePolicySuccess() {
            QuickPolicyRequest request = new QuickPolicyRequest();
            request.setPolicyName("Orders");
            request.setDescription("Orders policy");
            request.setEffect(Policy.Effect.ALLOW);
            request.setRoleIds(Set.of(1L));

            Role role = Role.builder().id(1L).roleName("ADMIN").build();
            Policy saved = Policy.builder().id(99L).name("Orders").build();
            when(roleService.getRole(1L)).thenReturn(role);
            when(policyRepository.findByName("AUTO_POLICY_FOR_ADMIN"))
                    .thenReturn(Optional.of(Policy.builder().id(10L).name("AUTO_POLICY_FOR_ADMIN").build()));
            when(businessPolicyService.createPolicyFromBusinessRule(any())).thenReturn(saved);

            ResponseEntity<PolicyQuickCreateResponse> response = controller.quickCreatePolicy(request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            PolicyQuickCreateResponse body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.success()).isTrue();
            assertThat(body.policyId()).isEqualTo(99L);
            assertThat(body.message()).isEqualTo("msg.policy.created");
            assertThat(body.warning()).contains("ADMIN");
        }

        @Test
        @DisplayName("quickCreatePolicy returns typed bad request response on duplicate policy name")
        void quickCreatePolicyDuplicate() {
            QuickPolicyRequest request = new QuickPolicyRequest();
            request.setPolicyName("Orders");
            when(businessPolicyService.createPolicyFromBusinessRule(any()))
                    .thenThrow(new DataIntegrityViolationException("duplicate"));

            ResponseEntity<PolicyQuickCreateResponse> response = controller.quickCreatePolicy(request);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).isEqualTo(new PolicyQuickCreateResponse(
                    false,
                    null,
                    "msg.policy.name.duplicate",
                    null
            ));
        }

        @Test
        @DisplayName("resetPolicyStatus rejects empty request with typed action response")
        void resetPolicyStatusEmpty() {
            ResponseEntity<PolicyActionResponse> response = controller.resetPolicyStatus(List.of());

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).isEqualTo(new PolicyActionResponse(
                    false,
                    "msg.policy.validation.target.required",
                    null
            ));
        }

        @Test
        @DisplayName("resetPolicyStatus counts only resources whose status is actually reset")
        void resetPolicyStatusCountsOnlyChangedResources() {
            ManagedResource changed = ManagedResource.builder()
                    .id(1L)
                    .resourceIdentifier("/api/changed")
                    .resourceType(ManagedResource.ResourceType.URL)
                    .status(ManagedResource.Status.PERMISSION_CREATED)
                    .build();
            ManagedResource unchanged = ManagedResource.builder()
                    .id(2L)
                    .resourceIdentifier("/api/unchanged")
                    .resourceType(ManagedResource.ResourceType.URL)
                    .status(ManagedResource.Status.NEEDS_DEFINITION)
                    .build();
            when(managedResourceRepository.findById(1L)).thenReturn(Optional.of(changed));
            when(managedResourceRepository.findById(2L)).thenReturn(Optional.of(unchanged));
            when(managedResourceRepository.findById(3L)).thenReturn(Optional.empty());

            ResponseEntity<PolicyActionResponse> response = controller.resetPolicyStatus(List.of(1L, 2L, 3L));

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(new PolicyActionResponse(true, null, 1));
            assertThat(changed.getStatus()).isEqualTo(ManagedResource.Status.NEEDS_DEFINITION);
            assertThat(unchanged.getStatus()).isEqualTo(ManagedResource.Status.NEEDS_DEFINITION);
            verify(managedResourceRepository).save(changed);
            verify(managedResourceRepository, never()).save(unchanged);
        }

        @Test
        @DisplayName("batchCreatePolicies rejects empty items with typed batch response")
        void batchCreatePoliciesEmptyItems() {
            BatchCreateRequest request = new BatchCreateRequest();

            ResponseEntity<PolicyBatchCreateResponse> response = controller.batchCreatePolicies(request);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).isEqualTo(new PolicyBatchCreateResponse(
                    false,
                    null,
                    null,
                    null,
                    "msg.policy.validation.target.required"
            ));
        }

        @Test
        @DisplayName("migratePolicyExpressionsToCrud returns typed migration response")
        void migratePolicyExpressionsToCrud() {
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());

            ResponseEntity<PolicyMigrationResponse> response = controller.migratePolicyExpressionsToCrud();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(new PolicyMigrationResponse(
                    true,
                    0,
                    null
            ));
        }

        @Test
        @DisplayName("migratePolicyExpressionsToCrud skips null expressions without failing the migration")
        void migratePolicyExpressionsToCrudSkipsNullExpressions() {
            PolicyCondition condition = PolicyCondition.builder()
                    .expression(null)
                    .build();
            PolicyRule rule = PolicyRule.builder().build();
            rule.addCondition(condition);
            Policy policy = Policy.builder()
                    .id(1L)
                    .name("NullExpressionPolicy")
                    .effect(Policy.Effect.ALLOW)
                    .priority(100)
                    .build();
            policy.addRule(rule);
            when(policyRepository.findAllWithDetails()).thenReturn(List.of(policy));

            ResponseEntity<PolicyMigrationResponse> response = controller.migratePolicyExpressionsToCrud();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(new PolicyMigrationResponse(true, 0, null));
            verify(policyRepository, never()).save(any(Policy.class));
        }

        @Test
        @DisplayName("cleanupOldAutoCreatedPermissions returns typed cleanup response")
        void cleanupOldAutoCreatedPermissions() {
            when(permissionRepository.findAll()).thenReturn(List.of());

            ResponseEntity<PolicyCleanupResponse> response = controller.cleanupOldAutoCreatedPermissions();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(new PolicyCleanupResponse(
                    true,
                    0,
                    null
            ));
        }
    }

    @Nested
    @DisplayName("typed version APIs")
    class TypedVersionApis {

        @Test
        @DisplayName("getVersions returns typed version summaries with existing fields")
        void getVersions() {
            LocalDateTime changedAt = LocalDateTime.of(2026, 4, 21, 10, 30);
            PolicyVersion version = PolicyVersion.builder()
                    .policyId(1L)
                    .versionNumber(2)
                    .changeType(PolicyVersion.ChangeType.UPDATED)
                    .changedBy("admin")
                    .changeReason("changed")
                    .changedAt(changedAt)
                    .build();
            when(policyService.getVersions(1L)).thenReturn(List.of(version));

            ResponseEntity<List<PolicyVersionSummaryResponse>> response = controller.getVersions(1L);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsExactly(new PolicyVersionSummaryResponse(
                    2,
                    "UPDATED",
                    "admin",
                    "changed",
                    "2026-04-21T10:30"
            ));
        }

        @Test
        @DisplayName("getVersionSnapshot returns typed snapshot DTO with existing fields")
        void getVersionSnapshot() {
            LocalDateTime changedAt = LocalDateTime.of(2026, 4, 21, 10, 30);
            PolicyVersion version = PolicyVersion.builder()
                    .policyId(1L)
                    .versionNumber(2)
                    .changeType(PolicyVersion.ChangeType.UPDATED)
                    .changedBy("admin")
                    .changeReason("changed")
                    .changedAt(changedAt)
                    .snapshotJson("{\"name\":\"Orders\"}")
                    .build();
            when(policyVersionService.getVersion(1L, 2)).thenReturn(Optional.of(version));

            ResponseEntity<PolicyVersionSnapshotResponse> response = controller.getVersionSnapshot(1L, 2);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(new PolicyVersionSnapshotResponse(
                    2,
                    "UPDATED",
                    "admin",
                    "changed",
                    "2026-04-21T10:30",
                    "{\"name\":\"Orders\"}",
                    null
            ));
        }

        @Test
        @DisplayName("rollbackPolicy accepts typed rollback request")
        void rollbackPolicy() {
            PolicyRollbackRequest request = new PolicyRollbackRequest("because");

            ResponseEntity<PolicyActionResponse> response = controller.rollbackPolicy(1L, 2, request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(new PolicyActionResponse(
                    true,
                    "msg.policy.rollback.success",
                    null
            ));
            verify(policyService).rollbackPolicy(1L, 2, "because");
        }

        @Test
        @DisplayName("compareVersions returns typed diff DTOs with existing fields")
        void compareVersions() {
            when(policyVersionService.compareVersions(1L, 1, 2)).thenReturn(List.of(Map.of(
                    "field", "name",
                    "before", "Old",
                    "after", "New"
            )));

            ResponseEntity<List<PolicyVersionDiffResponse>> response = controller.compareVersions(1L, 1, 2);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsExactly(new PolicyVersionDiffResponse(
                    "name",
                    "Old",
                    "New"
            ));
        }

        @Test
        @DisplayName("analyzeImpact returns typed error response on failure")
        void analyzeImpactError() {
            when(policyService.analyzeImpact(any())).thenThrow(new RuntimeException("boom"));

            ResponseEntity<PolicyApiResponse> response = controller.analyzeImpact(new PolicyCenterPolicyRequest());

            assertThat(response.getStatusCode().value()).isEqualTo(500);
            assertThat(response.getBody()).isEqualTo(new PolicyErrorResponse(
                    "msg.policy.impact.failed boom"
            ));
        }
    }

    @Nested
    @DisplayName("HTTP JSON contracts")
    class HttpJsonContracts {

        @Test
        @DisplayName("quick-create preserves top-level JSON fields")
        void quickCreatePreservesJsonFields() throws Exception {
            Policy saved = Policy.builder().id(99L).name("Orders").build();
            when(businessPolicyService.createPolicyFromBusinessRule(any())).thenReturn(saved);

            mockMvc.perform(post("/contexa/admin/policy-center/api/quick-create")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "policyName": "Orders",
                                      "description": "Orders policy",
                                      "roleIds": [],
                                      "permissionIds": [],
                                      "crudPermissions": ["READ"],
                                      "effect": "ALLOW"
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.policyId").value(99))
                    .andExpect(jsonPath("$.message").value("msg.policy.created"))
                    .andExpect(jsonPath("$.warning").doesNotExist());
        }

        @Test
        @DisplayName("available-permissions preserves page fields and dynamic rolePermissionMap")
        void availablePermissionsPreservesRolePermissionMap() throws Exception {
            Permission mappedPermission = Permission.builder().id(100L).name("READ").build();
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            role.getRolePermissions().add(RolePermission.builder()
                    .role(role)
                    .permission(mappedPermission)
                    .build());
            PermissionDto permission = PermissionDto.builder()
                    .id(101L)
                    .name("WRITE")
                    .friendlyName("Write")
                    .description("Write permission")
                    .targetType("CRUD")
                    .actionType("WRITE")
                    .linkedResourceIdentifier("/api/orders")
                    .build();
            when(roleService.getRole(10L)).thenReturn(role);
            when(permissionCatalogService.searchAvailablePermissions(eq("wri"), eq(Collections.emptySet()), any(Pageable.class)))
                    .thenReturn(new PageImpl<>(
                            List.of(permission),
                            PageRequest.of(0, 20),
                            1));

            mockMvc.perform(get("/contexa/admin/policy-center/api/available-permissions")
                            .param("keyword", "wri")
                            .param("roleIds", "10")
                            .param("size", "20"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.content[0].id").value(101))
                    .andExpect(jsonPath("$.content[0].friendlyName").value("Write"))
                    .andExpect(jsonPath("$.totalElements").value(1))
                    .andExpect(jsonPath("$.alreadyMappedIds[0]").value(100))
                    .andExpect(jsonPath("$.rolePermissionMap['10'][0]").value(100));
        }

        @Test
        @DisplayName("reset-policy-status serializes updated count from actual changes")
        void resetPolicyStatusSerializesActualUpdatedCount() throws Exception {
            ManagedResource changed = ManagedResource.builder()
                    .id(1L)
                    .resourceIdentifier("/api/changed")
                    .resourceType(ManagedResource.ResourceType.URL)
                    .status(ManagedResource.Status.PERMISSION_CREATED)
                    .build();
            ManagedResource unchanged = ManagedResource.builder()
                    .id(2L)
                    .resourceIdentifier("/api/unchanged")
                    .resourceType(ManagedResource.ResourceType.URL)
                    .status(ManagedResource.Status.NEEDS_DEFINITION)
                    .build();
            when(managedResourceRepository.findById(1L)).thenReturn(Optional.of(changed));
            when(managedResourceRepository.findById(2L)).thenReturn(Optional.of(unchanged));

            mockMvc.perform(post("/contexa/admin/policy-center/api/reset-policy-status")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("[1,2]"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.updated").value(1))
                    .andExpect(jsonPath("$.message").doesNotExist());
        }

        @Test
        @DisplayName("version snapshot error preserves error field without null metadata fields")
        void versionSnapshotErrorJsonContract() throws Exception {
            when(policyVersionService.getVersion(1L, 99)).thenReturn(Optional.empty());

            mockMvc.perform(get("/contexa/admin/policy-center/api/1/versions/99"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("Version not found"))
                    .andExpect(jsonPath("$.versionNumber").doesNotExist())
                    .andExpect(jsonPath("$.snapshot").doesNotExist());
        }

        @Test
        @DisplayName("rollback binds typed request body and preserves response fields")
        void rollbackBindsTypedRequestBody() throws Exception {
            mockMvc.perform(post("/contexa/admin/policy-center/api/1/rollback/2")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"reason\":\"because\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("msg.policy.rollback.success"))
                    .andExpect(jsonPath("$.updated").doesNotExist());

            verify(policyService).rollbackPolicy(1L, 2, "because");
        }

        @Test
        @DisplayName("conditions preserves list item fields")
        void conditionsPreservesJsonFields() throws Exception {
            ConditionTemplate template = ConditionTemplate.builder()
                    .id(7L)
                    .name("Owner Only")
                    .description("Owner can access")
                    .category("ownership")
                    .build();
            when(conditionTemplateRepository.findAll()).thenReturn(List.of(template));

            mockMvc.perform(get("/contexa/admin/policy-center/api/conditions")
                            .param("keyword", "owner"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(7))
                    .andExpect(jsonPath("$[0].name").value("Owner Only"))
                    .andExpect(jsonPath("$[0].description").value("Owner can access"))
                    .andExpect(jsonPath("$[0].category").value("ownership"));
        }

        @Test
        @DisplayName("validation-report preserves report fields")
        void validationReportPreservesJsonFields() throws Exception {
            when(policyValidationService.validateAll())
                    .thenReturn(new FullValidationReport(2, "HEALTHY", List.of(), List.of()));

            mockMvc.perform(get("/contexa/admin/policy-center/api/validation-report"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalPolicies").value(2))
                    .andExpect(jsonPath("$.healthStatus").value("HEALTHY"))
                    .andExpect(jsonPath("$.conflicts").isArray())
                    .andExpect(jsonPath("$.duplicates").isArray());
        }

        @Test
        @DisplayName("validate binds controller policy DTO and preserves report fields")
        void validateBindsControllerPolicyDto() throws Exception {
            when(policyService.validateBeforeCreate(any(PolicyDto.class)))
                    .thenReturn(new PolicyValidationReport(List.of(), List.of(), true, null));

            mockMvc.perform(post("/contexa/admin/policy-center/api/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name": "Orders",
                                      "description": "Orders policy",
                                      "effect": "ALLOW",
                                      "priority": 25,
                                      "targets": [
                                        {
                                          "targetType": "URL",
                                          "targetIdentifier": "/api/orders",
                                          "httpMethod": "GET",
                                          "targetOrder": 1,
                                          "sourceType": "RESOURCE"
                                        }
                                      ],
                                      "rules": [
                                        {
                                          "description": "rule",
                                          "conditions": [
                                            {
                                              "expression": "hasAuthority('READ')",
                                              "authorizationPhase": "PRE_AUTHORIZE"
                                            }
                                          ]
                                        }
                                      ]
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.conflicts").isArray())
                    .andExpect(jsonPath("$.duplicates").isArray())
                    .andExpect(jsonPath("$.canCreate").value(true));

            verify(policyService).validateBeforeCreate(argThat(dto ->
                    "Orders".equals(dto.getName())
                            && dto.getEffect() == Policy.Effect.ALLOW
                            && dto.getPriority() == 25
                            && dto.getTargets().size() == 1
                            && "/api/orders".equals(dto.getTargets().get(0).getTargetIdentifier())
                            && dto.getRules().size() == 1
                            && dto.getRules().get(0).getConditions().size() == 1
                            && dto.getRules().get(0).getConditions().get(0).getAuthorizationPhase()
                                    == PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE));
        }

        @Test
        @DisplayName("validate-quick preserves validation failure fields")
        void validateQuickPreservesFailureFields() throws Exception {
            when(policyService.validateBeforeCreate(any(PolicyDto.class)))
                    .thenReturn(new PolicyValidationReport(
                            List.of(),
                            List.of(),
                            false,
                            "blocked"));

            mockMvc.perform(post("/contexa/admin/policy-center/api/validate-quick")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "policyName": "Orders",
                                      "description": "Orders policy",
                                      "roleIds": [],
                                      "permissionIds": [],
                                      "crudPermissions": ["READ"],
                                      "effect": "DENY"
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.canCreate").value(false))
                    .andExpect(jsonPath("$.blockedReason").value("blocked"));
        }

        @Test
        @DisplayName("ai-validation preserves item fields")
        void aiValidationPreservesJsonFields() throws Exception {
            when(policyService.validateAIPolicy(10L)).thenReturn(new AIPolicyValidationReport(
                    List.of(new AIPolicyValidationReport.ValidationItem(
                            "conflict",
                            AIPolicyValidationReport.CheckResult.PASS,
                            "ok")),
                    true,
                    null));

            mockMvc.perform(get("/contexa/admin/policy-center/api/10/ai-validation"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.items[0].checkName").value("conflict"))
                    .andExpect(jsonPath("$.items[0].result").value("PASS"))
                    .andExpect(jsonPath("$.items[0].detail").value("ok"))
                    .andExpect(jsonPath("$.canApprove").value(true));
        }

        @Test
        @DisplayName("simulate binds request and preserves summary fields")
        void simulatePreservesJsonFields() throws Exception {
            when(policyService.simulate(any(PolicyDto.class), anyList())).thenReturn(new SimulationReport(
                    List.of(),
                    new SimulationReport.SimulationSummary(1, 2, 3, 4)));

            mockMvc.perform(post("/contexa/admin/policy-center/api/simulate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "candidatePolicy": {
                                        "name": "Orders",
                                        "effect": "ALLOW"
                                      },
                                      "testCases": [
                                        {
                                          "userId": 1,
                                          "targetType": "URL",
                                          "path": "/api/orders",
                                          "httpMethod": "GET"
                                        }
                                      ]
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.results").isArray())
                    .andExpect(jsonPath("$.summary.unchanged").value(1))
                    .andExpect(jsonPath("$.summary.allowToDeny").value(2))
                    .andExpect(jsonPath("$.summary.denyToAllow").value(3))
                    .andExpect(jsonPath("$.summary.otherChanges").value(4));
        }

        @Test
        @DisplayName("impact-analysis preserves success response fields")
        void impactAnalysisPreservesJsonFields() throws Exception {
            when(policyService.analyzeImpact(any(PolicyDto.class))).thenReturn(new PolicyImpactReport(
                    1,
                    List.of(new PolicyImpactReport.AffectedUser(
                            1L,
                            "admin",
                            List.of("ADMIN"),
                            List.of("operators"),
                            "DENY",
                            "ALLOW",
                            "GAINED")),
                    List.of(new PolicyImpactReport.AffectedResource(
                            "/api/orders",
                            "GET",
                            1,
                            List.of("Orders"))),
                    new PolicyImpactReport.AccessChangeSummary(1, 0, 0, 0)));

            mockMvc.perform(post("/contexa/admin/policy-center/api/impact-analysis")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"Orders\",\"effect\":\"ALLOW\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.affectedUserCount").value(1))
                    .andExpect(jsonPath("$.affectedUsers[0].username").value("admin"))
                    .andExpect(jsonPath("$.affectedResources[0].identifier").value("/api/orders"))
                    .andExpect(jsonPath("$.accessChangeSummary.gained").value(1));
        }

        @Test
        @DisplayName("matrix preserves nested matrix fields")
        void matrixPreservesJsonFields() throws Exception {
            when(policyMatrixService.generateMatrix("orders", "ADMIN")).thenReturn(new PolicyMatrixReport(
                    List.of(new PolicyMatrixReport.ResourceEntry("/api/orders", "GET", "Orders")),
                    List.of("ADMIN"),
                    List.of(List.of(new PolicyMatrixReport.MatrixCell(
                            "ALLOW",
                            10L,
                            "OrdersPolicy",
                            false))),
                    List.of(new PolicyMatrixReport.ConflictCell(0, 0, "HIGH"))));

            mockMvc.perform(get("/contexa/admin/policy-center/api/matrix")
                            .param("resourceFilter", "orders")
                            .param("roleFilter", "ADMIN"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.resources[0].identifier").value("/api/orders"))
                    .andExpect(jsonPath("$.roles[0]").value("ADMIN"))
                    .andExpect(jsonPath("$.cells[0][0].access").value("ALLOW"))
                    .andExpect(jsonPath("$.conflictCells[0].severity").value("HIGH"))
                    .andExpect(jsonPath("$.totalRoles").value(1));
        }

        @Test
        @DisplayName("batch-create success preserves result fields")
        void batchCreateSuccessPreservesJsonFields() throws Exception {
            Role role = Role.builder().id(1L).roleName("ADMIN").build();
            Policy saved = Policy.builder()
                    .id(50L)
                    .name("ALLOW_ADMIN_READ_API_ORDERS")
                    .build();
            when(roleService.getRole(1L)).thenReturn(role);
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(policyValidationService.validate(any(Policy.class), anyList()))
                    .thenReturn(new PolicyValidationReport(List.of(), List.of(), true, null));
            when(policyRepository.save(any(Policy.class))).thenReturn(saved);

            mockMvc.perform(post("/contexa/admin/policy-center/api/batch-create")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "roleIds": [1],
                                      "effect": "ALLOW",
                                      "items": [
                                        {
                                          "resourceIdentifier": "/api/orders",
                                          "resourceType": "URL",
                                          "httpMethod": "GET",
                                          "crudPermissions": ["READ"]
                                        }
                                      ]
                                    }
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.created").value(1))
                    .andExpect(jsonPath("$.total").value(1))
                    .andExpect(jsonPath("$.results[0].resourceIdentifier").value("/api/orders"))
                    .andExpect(jsonPath("$.results[0].status").value("CREATED"))
                    .andExpect(jsonPath("$.results[0].policyId").value(50))
                    .andExpect(jsonPath("$.results[0].policyName").value("ALLOW_ADMIN_READ_API_ORDERS"));
        }
    }
}
