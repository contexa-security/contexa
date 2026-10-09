package io.contexa.contexaiam.admin;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The admin console under /contexa/admin is for administrators: besides the URL policy, every controller of the area
 * requires the administrator role itself, so a policy edited too wide never opens it to every signed-in user. Only the
 * login page and the self-service paths a signed-in user needs (asking for the release of a block, following a pending
 * analysis) are left to the URL policy.
 */
class AdminConsoleAuthorizationContractTest {

    private static final String ADMIN_AREA = "/contexa/admin";
    private static final Set<String> SELF_SERVICE = Set.of(
            "io.contexa.contexaiam.admin.web.auth.controller.LoginController",
            "io.contexa.contexaiam.aiam.web.ZeroTrustUnblockController",
            "io.contexa.contexaiam.aiam.web.ZeroTrustSseController");

    @Test
    void everyAdminConsoleControllerRequiresTheAdministratorRole() {
        List<Class<?>> controllers = adminAreaControllers();
        List<String> unguarded = new ArrayList<>();
        for (Class<?> controller : controllers) {
            if (SELF_SERVICE.contains(controller.getName())) {
                continue;
            }
            PreAuthorize guard = AnnotatedElementUtils.findMergedAnnotation(controller, PreAuthorize.class);
            if (guard == null || !(guard.value().contains("hasRole('ADMIN')")
                    || guard.value().contains("hasAnyRole('ADMIN')"))) {
                unguarded.add(controller.getName());
            }
        }

        assertThat(controllers).as("the admin console controllers were found").hasSizeGreaterThan(20);
        assertThat(unguarded).isEmpty();
    }

    @Test
    void theSelfServicePathsStayOpenToSignedInUsers() {
        List<String> selfService = adminAreaControllers().stream().map(Class::getName)
                .filter(SELF_SERVICE::contains).toList();

        assertThat(selfService).containsExactlyInAnyOrderElementsOf(SELF_SERVICE);
        for (String name : SELF_SERVICE) {
            Class<?> controller = ClassUtils.resolveClassName(name, getClass().getClassLoader());
            assertThat(AnnotatedElementUtils.findMergedAnnotation(controller, PreAuthorize.class))
                    .as(name + " is used by users who are not administrators").isNull();
        }
    }

    private List<Class<?>> adminAreaControllers() {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Controller.class));
        List<Class<?>> controllers = new ArrayList<>();
        for (BeanDefinition candidate : scanner.findCandidateComponents("io.contexa.contexaiam")) {
            Class<?> type = ClassUtils.resolveClassName(candidate.getBeanClassName(), getClass().getClassLoader());
            if (servesAdminArea(type)) {
                controllers.add(type);
            }
        }
        return controllers;
    }

    private static boolean servesAdminArea(Class<?> type) {
        RequestMapping classMapping = AnnotatedElementUtils.findMergedAnnotation(type, RequestMapping.class);
        if (classMapping != null && paths(classMapping).anyMatch(path -> path.startsWith(ADMIN_AREA))) {
            return true;
        }
        for (Method method : type.getDeclaredMethods()) {
            RequestMapping mapping = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);
            if (mapping != null && paths(mapping).anyMatch(path -> path.startsWith(ADMIN_AREA))) {
                return true;
            }
        }
        return false;
    }

    private static Stream<String> paths(RequestMapping mapping) {
        return Stream.concat(Arrays.stream(mapping.value()), Arrays.stream(mapping.path()));
    }
}
