package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CompositePermissionEvaluatorTest {

    @Mock
    private Authentication authentication;

    @Mock
    private ApplicationContext applicationContext;

    private CompositePermissionEvaluator compositeEvaluator;

    // Concrete test evaluator that exposes domain for sorting verification
    static class StubDomainEvaluator extends AbstractDomainPermissionEvaluator {
        private final String domainName;
        private final ApplicationContext ctx;
        private boolean hasPermissionResult = false;

        StubDomainEvaluator(String domainName, ApplicationContext ctx) {
            this.domainName = domainName;
            this.ctx = ctx;
        }

        void setHasPermissionResult(boolean result) {
            this.hasPermissionResult = result;
        }

        @Override
        protected String domain() {
            return domainName;
        }

        @Override
        protected String repositoryBeanName() {
            return domainName.toLowerCase() + "Repository";
        }

        @Override
        protected ApplicationContext getApplicationContext() {
            return ctx;
        }

        @Override
        public boolean hasPermission(Authentication auth, Object target, Object permission) {
            return hasPermissionResult;
        }

        @Override
        public boolean hasPermission(Authentication auth, java.io.Serializable targetId, String targetType, Object permission) {
            return hasPermissionResult;
        }
    }

    @Nested
    @DisplayName("Evaluator sorting by domain length")
    class SortingTest {

        @Test
        @DisplayName("Should sort evaluators by domain length in descending order (longest first)")
        void shouldSortByDomainLengthDescending() {
            StubDomainEvaluator shortDomain = new StubDomainEvaluator("A", applicationContext);
            StubDomainEvaluator mediumDomain = new StubDomainEvaluator("ABC", applicationContext);
            StubDomainEvaluator longDomain = new StubDomainEvaluator("ABCDE", applicationContext);

            // Provide in wrong order to verify sorting
            compositeEvaluator = new CompositePermissionEvaluator(List.of(shortDomain, longDomain, mediumDomain));

            // The longest-domain evaluator "ABCDE" should be checked first.
            // If we ask for "ABCDE_READ", the longDomain evaluator should match.
            longDomain.setHasPermissionResult(true);
            when(authentication.isAuthenticated()).thenReturn(true);

            boolean result = compositeEvaluator.hasPermission(authentication, null, "ABCDE_READ");

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("hasPermission(authentication, targetDomainObject, permission)")
    class HasPermissionWithObjectTest {

        @Test
        @DisplayName("Should return false when authentication is null")
        void shouldReturnFalseWhenAuthIsNull() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));

            assertThat(compositeEvaluator.hasPermission(null, new Object(), "USER_READ")).isFalse();
        }

        @Test
        @DisplayName("Should return false when not authenticated")
        void shouldReturnFalseWhenNotAuthenticated() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));
            when(authentication.isAuthenticated()).thenReturn(false);

            assertThat(compositeEvaluator.hasPermission(authentication, new Object(), "USER_READ")).isFalse();
        }

        @Test
        @DisplayName("Should return false when no evaluator supports the permission")
        void shouldReturnFalseWhenNoEvaluatorSupports() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));
            when(authentication.isAuthenticated()).thenReturn(true);

            // "ROLE_READ" does not match domain "USER"
            assertThat(compositeEvaluator.hasPermission(authentication, new Object(), "ROLE_READ")).isFalse();
        }

        @Test
        @DisplayName("Should delegate to matching evaluator when permission matches domain")
        void shouldDelegateToMatchingEvaluator() {
            StubDomainEvaluator userEval = new StubDomainEvaluator("USER", applicationContext);
            userEval.setHasPermissionResult(true);
            StubDomainEvaluator roleEval = new StubDomainEvaluator("ROLE", applicationContext);

            compositeEvaluator = new CompositePermissionEvaluator(List.of(userEval, roleEval));
            when(authentication.isAuthenticated()).thenReturn(true);

            assertThat(compositeEvaluator.hasPermission(authentication, new Object(), "USER_READ")).isTrue();
        }

        @Test
        @DisplayName("Should return true when permission is null and target is not null")
        void shouldReturnTrueWhenPermissionNullAndTargetNotNull() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));
            when(authentication.isAuthenticated()).thenReturn(true);

            assertThat(compositeEvaluator.hasPermission(authentication, new Object(), null)).isTrue();
        }

        @Test
        @DisplayName("Should return false when permission is null and target is null")
        void shouldReturnFalseWhenPermissionNullAndTargetNull() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));
            when(authentication.isAuthenticated()).thenReturn(true);

            assertThat(compositeEvaluator.hasPermission(authentication, null, null)).isFalse();
        }
    }

    @Nested
    @DisplayName("hasPermission(authentication, targetId, targetType, permission)")
    class HasPermissionWithTargetIdTest {

        @Test
        @DisplayName("Should return false when authentication is null")
        void shouldReturnFalseWhenAuthIsNull() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));

            assertThat(compositeEvaluator.hasPermission(null, 1L, "USER", "READ")).isFalse();
        }

        @Test
        @DisplayName("Should delegate to evaluator matching target type")
        void shouldDelegateToMatchingTargetType() {
            StubDomainEvaluator userEval = new StubDomainEvaluator("USER", applicationContext);
            userEval.setHasPermissionResult(true);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(userEval));
            when(authentication.isAuthenticated()).thenReturn(true);

            assertThat(compositeEvaluator.hasPermission(authentication, 1L, "USER", "READ")).isTrue();
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when no evaluator matches target type")
        void shouldThrowWhenNoEvaluatorMatchesTargetType() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));
            when(authentication.isAuthenticated()).thenReturn(true);

            assertThatThrownBy(() -> compositeEvaluator.hasPermission(authentication, 1L, "ORDER", "READ"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ORDER");
        }
    }

    @Nested
    @DisplayName("resolveEntity")
    class ResolveEntityTest {

        @Test
        @DisplayName("Should delegate entity resolution to matching evaluator")
        void shouldDelegateResolveEntity() {
            StubDomainEvaluator userEval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(userEval));

            // resolveEntity on StubDomainEvaluator calls super which uses applicationContext
            when(applicationContext.containsBean("userRepository")).thenReturn(false);

            // Should not throw - returns null from failed resolution
            Object result = compositeEvaluator.resolveEntity(1L, "USER");
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should throw when no evaluator matches target type for resolveEntity")
        void shouldThrowWhenNoEvaluatorForResolveEntity() {
            StubDomainEvaluator eval = new StubDomainEvaluator("USER", applicationContext);
            compositeEvaluator = new CompositePermissionEvaluator(List.of(eval));

            assertThatThrownBy(() -> compositeEvaluator.resolveEntity(1L, "UNKNOWN"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("UNKNOWN");
        }
    }
}
