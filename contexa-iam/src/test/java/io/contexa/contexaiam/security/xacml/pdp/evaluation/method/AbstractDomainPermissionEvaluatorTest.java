package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.security.authority.PermissionAuthority;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AbstractDomainPermissionEvaluatorTest {

    private static final String DOMAIN = "USER";
    private static final String REPO_BEAN = "userRepository";

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private Authentication authentication;

    private TestDomainPermissionEvaluator evaluator;

    // Concrete subclass for testing the abstract class
    static class TestDomainPermissionEvaluator extends AbstractDomainPermissionEvaluator {
        private final ApplicationContext ctx;

        TestDomainPermissionEvaluator(ApplicationContext ctx) {
            this.ctx = ctx;
        }

        @Override
        protected String domain() {
            return DOMAIN;
        }

        @Override
        protected String repositoryBeanName() {
            return REPO_BEAN;
        }

        @Override
        protected ApplicationContext getApplicationContext() {
            return ctx;
        }
    }

    @BeforeEach
    void setUp() {
        evaluator = new TestDomainPermissionEvaluator(applicationContext);
    }

    @Nested
    @DisplayName("CRUD synonym resolution")
    class CrudSynonymResolutionTest {

        @ParameterizedTest
        @ValueSource(strings = {"read", "get", "view", "list", "fetch", "find", "retrieve", "search"})
        @DisplayName("Should resolve read-group synonyms")
        void shouldResolveReadGroupSynonyms(String action) {
            List<String> synonyms = AbstractDomainPermissionEvaluator.resolveCrudSynonyms(action);

            assertThat(synonyms).contains("GET", "READ", "VIEW", "LIST");
        }

        @ParameterizedTest
        @ValueSource(strings = {"create", "save", "add", "insert", "register", "post"})
        @DisplayName("Should resolve create-group synonyms")
        void shouldResolveCreateGroupSynonyms(String action) {
            List<String> synonyms = AbstractDomainPermissionEvaluator.resolveCrudSynonyms(action);

            assertThat(synonyms).contains("CREATE", "SAVE", "ADD");
        }

        @ParameterizedTest
        @ValueSource(strings = {"update", "edit", "modify", "change", "patch", "put"})
        @DisplayName("Should resolve update-group synonyms")
        void shouldResolveUpdateGroupSynonyms(String action) {
            List<String> synonyms = AbstractDomainPermissionEvaluator.resolveCrudSynonyms(action);

            assertThat(synonyms).contains("UPDATE", "EDIT", "MODIFY");
        }

        @ParameterizedTest
        @ValueSource(strings = {"delete", "remove", "destroy", "drop", "erase", "purge"})
        @DisplayName("Should resolve delete-group synonyms")
        void shouldResolveDeleteGroupSynonyms(String action) {
            List<String> synonyms = AbstractDomainPermissionEvaluator.resolveCrudSynonyms(action);

            assertThat(synonyms).contains("DELETE", "REMOVE", "DESTROY");
        }

        @Test
        @DisplayName("Should return single-element list for unknown action")
        void shouldReturnSingleElementForUnknownAction() {
            List<String> synonyms = AbstractDomainPermissionEvaluator.resolveCrudSynonyms("CUSTOM_ACTION");

            assertThat(synonyms).containsExactly("CUSTOM_ACTION");
        }
    }

    @Nested
    @DisplayName("supportsTargetType")
    class SupportsTargetTypeTest {

        @Test
        @DisplayName("Should return true for matching domain (case-insensitive)")
        void shouldSupportMatchingDomain() {
            assertThat(evaluator.supportsTargetType("user")).isTrue();
            assertThat(evaluator.supportsTargetType("USER")).isTrue();
            assertThat(evaluator.supportsTargetType("User")).isTrue();
        }

        @Test
        @DisplayName("Should return false for non-matching domain")
        void shouldNotSupportNonMatchingDomain() {
            assertThat(evaluator.supportsTargetType("ROLE")).isFalse();
        }
    }

    @Nested
    @DisplayName("supportsPermission")
    class SupportsPermissionTest {

        @Test
        @DisplayName("Should support permission starting with domain prefix")
        void shouldSupportPermissionWithDomainPrefix() {
            assertThat(evaluator.supportsPermission("USER_READ")).isTrue();
            assertThat(evaluator.supportsPermission("user_delete")).isTrue();
        }

        @Test
        @DisplayName("Should not support permission without domain prefix")
        void shouldNotSupportPermissionWithoutDomainPrefix() {
            assertThat(evaluator.supportsPermission("ROLE_READ")).isFalse();
        }

        @Test
        @DisplayName("Should return false for null permission")
        void shouldReturnFalseForNullPermission() {
            assertThat(evaluator.supportsPermission(null)).isFalse();
        }
    }

    @Nested
    @DisplayName("checkPermission with PermissionAuthority")
    class CheckPermissionTest {

        @Test
        @DisplayName("Should grant permission when authority matches via synonym")
        void shouldGrantPermissionWhenAuthorityMatchesViaSynonym() {
            PermissionAuthority permAuth = mock(PermissionAuthority.class);
            when(permAuth.getAuthority()).thenReturn("USER_GET");
            when(permAuth.getTargetType()).thenReturn("METHOD");

            Collection<GrantedAuthority> authorities = List.of(permAuth);
            doReturn(authorities).when(authentication).getAuthorities();
            when(authentication.isAuthenticated()).thenReturn(true);

            // "read" is a synonym of "get"
            boolean result = evaluator.checkPermission(authentication, "USER_READ");

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should deny permission when no matching authority exists")
        void shouldDenyPermissionWhenNoMatchingAuthority() {
            PermissionAuthority permAuth = mock(PermissionAuthority.class);
            when(permAuth.getAuthority()).thenReturn("ROLE_DELETE");
            when(permAuth.getTargetType()).thenReturn("METHOD");

            Collection<GrantedAuthority> authorities = List.of(permAuth);
            doReturn(authorities).when(authentication).getAuthorities();

            boolean result = evaluator.checkPermission(authentication, "USER_READ");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return true when permission is null")
        void shouldReturnTrueWhenPermissionIsNull() {
            boolean result = evaluator.checkPermission(authentication, null);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should ignore non-METHOD target type authorities")
        void shouldIgnoreNonMethodTargetType() {
            PermissionAuthority permAuth = mock(PermissionAuthority.class);
            when(permAuth.getAuthority()).thenReturn("USER_READ");
            when(permAuth.getTargetType()).thenReturn("URL");

            Collection<GrantedAuthority> authorities = List.of(permAuth);
            doReturn(authorities).when(authentication).getAuthorities();

            boolean result = evaluator.checkPermission(authentication, "USER_READ");

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("hasPermission(authentication, targetDomainObject, permission)")
    class HasPermissionWithTargetObjectTest {

        @Test
        @DisplayName("Should return false when authentication is null")
        void shouldReturnFalseWhenAuthIsNull() {
            assertThat(evaluator.hasPermission(null, new Object(), "USER_READ")).isFalse();
        }

        @Test
        @DisplayName("Should return false when not authenticated")
        void shouldReturnFalseWhenNotAuthenticated() {
            when(authentication.isAuthenticated()).thenReturn(false);

            assertThat(evaluator.hasPermission(authentication, new Object(), "USER_READ")).isFalse();
        }
    }

    @Nested
    @DisplayName("resolveEntity via reflection")
    class ResolveEntityTest {

        @Test
        @DisplayName("Should return null when targetId is null")
        void shouldReturnNullWhenTargetIdIsNull() {
            assertThat(evaluator.resolveEntity(null)).isNull();
        }

        @Test
        @DisplayName("Should return null when bean is not found")
        void shouldReturnNullWhenBeanNotFound() {
            when(applicationContext.containsBean(REPO_BEAN)).thenReturn(false);

            assertThat(evaluator.resolveEntity(1L)).isNull();
        }

        @Test
        @DisplayName("Should resolve entity via findById reflection call")
        void shouldResolveEntityViaReflection() throws Exception {
            Object expectedEntity = new Object();
            Object repository = mock(Object.class);

            when(applicationContext.containsBean(REPO_BEAN)).thenReturn(true);
            when(applicationContext.getBean(REPO_BEAN)).thenReturn(repository);

            // Create a real repository-like object with findById
            FakeRepository fakeRepo = new FakeRepository(expectedEntity);
            when(applicationContext.getBean(REPO_BEAN)).thenReturn(fakeRepo);

            Object result = evaluator.resolveEntity(1L);

            assertThat(result).isEqualTo(expectedEntity);
        }

        @Test
        @DisplayName("Should return null when findById returns empty Optional")
        void shouldReturnNullWhenOptionalEmpty() {
            FakeRepository fakeRepo = new FakeRepository(null);
            when(applicationContext.containsBean(REPO_BEAN)).thenReturn(true);
            when(applicationContext.getBean(REPO_BEAN)).thenReturn(fakeRepo);

            Object result = evaluator.resolveEntity(1L);

            assertThat(result).isNull();
        }
    }

    // Fake repository class for reflection-based resolveEntity tests
    public static class FakeRepository {
        private final Object entity;

        public FakeRepository(Object entity) {
            this.entity = entity;
        }

        public Optional<Object> findById(Object id) {
            return Optional.ofNullable(entity);
        }
    }
}
