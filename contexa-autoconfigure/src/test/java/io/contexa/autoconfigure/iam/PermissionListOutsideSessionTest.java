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

import com.querydsl.jpa.impl.JPAQueryFactory;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.admin.web.auth.controller.PermissionController;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.impl.PermissionServiceImpl;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.Hibernate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The console's permission screens on the real queries, with no session open while the screen is built: the controller
 * reads the resource a permission guards after the service has returned, as the request does. The test runs without a
 * transaction of its own, so the service's transaction is the only session there is.
 */
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.liquibase.enabled=false"
})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class PermissionListOutsideSessionTest {

    private static final Pageable FIRST_PAGE = PageRequest.of(0, 15, Sort.by(Sort.Direction.DESC, "id"));

    @Autowired
    private PermissionService service;

    @Autowired
    private PermissionRepository permissions;

    @Autowired
    private ManagedResourceRepository resources;

    private PermissionController controller;
    private Long guardingId;
    private Long plainId;
    private Long resourceId;

    @BeforeEach
    void aPermissionThatGuardsAResourceAndOneThatDoesNot() {
        permissions.deleteAll();
        resources.deleteAll();

        ManagedResource resource = resources.save(ManagedResource.builder()
                .resourceIdentifier("/rc/counts")
                .resourceType(ManagedResource.ResourceType.URL)
                .friendlyName("RC counts")
                .status(ManagedResource.Status.PERMISSION_CREATED)
                .build());
        resourceId = resource.getId();
        guardingId = permissions.save(Permission.builder()
                .name("URL_RC_COUNTS").friendlyName("RC counts").targetType("URL").actionType("GET")
                .managedResource(resource).build()).getId();
        plainId = permissions.save(Permission.builder()
                .name("PLAIN_PERMISSION").friendlyName("Plain").targetType("URL").actionType("GET").build()).getId();

        controller = new PermissionController(service, new ModelMapper(), mock(FunctionCatalogService.class),
                new StaticMessageSource());
    }

    @SuppressWarnings("unchecked")
    private static List<PermissionDto> listed(Model model) {
        return (List<PermissionDto>) model.getAttribute("permissions");
    }

    private PermissionDto named(List<PermissionDto> listed, String name) {
        return listed.stream().filter(dto -> name.equals(dto.getName())).findFirst().orElseThrow();
    }

    @Test
    @DisplayName("the list opens when a permission guards a resource, and shows the resource it guards")
    void theListOpensWithAGuardedResource() {
        Model model = new ConcurrentModel();

        String view = controller.getPermissions(null, FIRST_PAGE, model);

        assertThat(view).isEqualTo("contexa/admin/permissions");
        List<PermissionDto> listed = listed(model);
        assertThat(listed).extracting(PermissionDto::getName).containsExactly("PLAIN_PERMISSION", "URL_RC_COUNTS");
        assertThat(named(listed, "URL_RC_COUNTS").getLinkedResourceId()).isEqualTo(resourceId);
        assertThat(named(listed, "URL_RC_COUNTS").getLinkedResourceIdentifier()).isEqualTo("/rc/counts");
        assertThat(named(listed, "PLAIN_PERMISSION").getLinkedResourceId()).isNull();
        assertThat(named(listed, "PLAIN_PERMISSION").getLinkedResourceIdentifier()).isNull();
    }

    @Test
    @DisplayName("the keyword search opens when a permission found guards a resource, and counts the permissions found")
    void theKeywordSearchOpensWithAGuardedResource() {
        Model model = new ConcurrentModel();

        controller.getPermissions("rc_counts", FIRST_PAGE, model);

        assertThat(listed(model)).extracting(PermissionDto::getName).containsExactly("URL_RC_COUNTS");
        assertThat(named(listed(model), "URL_RC_COUNTS").getLinkedResourceIdentifier()).isEqualTo("/rc/counts");
        assertThat(((Page<?>) model.getAttribute("page")).getTotalElements()).isEqualTo(1);
    }

    @Test
    @DisplayName("the search keeps taking the characters of the keyword as they are")
    void theKeywordSearchTakesTheWildcardsAsTheyAre() {
        Model model = new ConcurrentModel();

        controller.getPermissions("RC%COUNTS", FIRST_PAGE, model);

        assertThat(listed(model)).isEmpty();
    }

    @Test
    @DisplayName("a page of the list is a page, in the order asked for")
    void aPageOfTheListIsAPage() {
        Model model = new ConcurrentModel();

        controller.getPermissions(null, PageRequest.of(1, 1, Sort.by(Sort.Direction.DESC, "id")), model);

        assertThat(listed(model)).extracting(PermissionDto::getName).containsExactly("URL_RC_COUNTS");
        assertThat(((Page<?>) model.getAttribute("page")).getTotalElements()).isEqualTo(2);
    }

    @Test
    @DisplayName("the details of a permission open when it guards a resource, and show the resource")
    void theDetailsOpenWithAGuardedResource() {
        Model model = new ConcurrentModel();

        String view = controller.permissionDetails(guardingId, model, new RedirectAttributesModelMap());

        assertThat(view).isEqualTo("contexa/admin/permissiondetails");
        PermissionDto shown = (PermissionDto) model.getAttribute("permission");
        assertThat(shown.getLinkedResourceId()).isEqualTo(resourceId);
        assertThat(shown.getLinkedResourceIdentifier()).isEqualTo("/rc/counts");
    }

    @Test
    @DisplayName("the details of a permission without a resource open without one")
    void theDetailsOpenWithoutAResource() {
        Model model = new ConcurrentModel();

        controller.permissionDetails(plainId, model, new RedirectAttributesModelMap());

        assertThat(((PermissionDto) model.getAttribute("permission")).getLinkedResourceId()).isNull();
    }

    @Test
    @DisplayName("the permission an update hands back, which the details page is given from the cache, carries its resource")
    void anUpdatedPermissionCarriesItsResource() {
        PermissionDto change = PermissionDto.builder().name("URL_RC_COUNTS").friendlyName("Renamed")
                .targetType("URL").actionType("GET").build();

        Permission updated = service.updatePermission(guardingId, change);

        assertThat(Hibernate.isInitialized(updated.getManagedResource())).isTrue();
        assertThat(updated.getManagedResource().getResourceIdentifier()).isEqualTo("/rc/counts");
    }

    @Test
    @DisplayName("the permissions the role screens offer are mapped without a session, with or without a resource")
    void theRoleScreensMapAllPermissionsWithoutASession() {
        ModelMapper mapper = new ModelMapper();

        List<PermissionDto> offered = service.getAllPermissions().stream()
                .map(permission -> mapper.map(permission, PermissionDto.class)).toList();

        assertThat(offered).extracting(PermissionDto::getName).containsExactlyInAnyOrder("URL_RC_COUNTS", "PLAIN_PERMISSION");
    }

    @SpringBootConfiguration
    @EntityScan(basePackageClasses = {Users.class, Policy.class})
    @EnableJpaRepositories(basePackageClasses = {PermissionRepository.class, ManagedResourceRepository.class},
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE,
                    classes = {PermissionRepository.class, ManagedResourceRepository.class, PolicyRepository.class}))
    static class Persistence {

        @Bean(name = "transactionManager")
        PlatformTransactionManager transactionManager(EntityManagerFactory entityManagerFactory) {
            return new JpaTransactionManager(entityManagerFactory);
        }

        @Bean(name = "contexaTransactionManager")
        PlatformTransactionManager contexaTransactionManager(EntityManagerFactory entityManagerFactory) {
            return new JpaTransactionManager(entityManagerFactory);
        }

        @Bean
        JPAQueryFactory jpaQueryFactory(EntityManager entityManager) {
            return new JPAQueryFactory(entityManager);
        }

        @Bean
        PermissionService permissionService(PermissionRepository permissionRepository,
                                            ManagedResourceRepository managedResourceRepository,
                                            PolicyRepository policyRepository) {
            return new PermissionServiceImpl(permissionRepository, managedResourceRepository, policyRepository,
                    messageSource(), mock(LastAdministratorGuard.class));
        }

        @Bean
        MessageSource messageSource() {
            return new StaticMessageSource();
        }
    }
}
