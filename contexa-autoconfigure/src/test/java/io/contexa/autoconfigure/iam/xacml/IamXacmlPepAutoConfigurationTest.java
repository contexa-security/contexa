package io.contexa.autoconfigure.iam.xacml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests IamXacmlPepAutoConfiguration annotation structure and bean definitions.
 * Uses reflection instead of ApplicationContextRunner due to complex transitive dependencies.
 */
@DisplayName("IamXacmlPepAutoConfiguration")
class IamXacmlPepAutoConfigurationTest {

    @Nested
    @DisplayName("Class-level annotations")
    class ClassAnnotations {

        @Test
        @DisplayName("Should be annotated with @AutoConfiguration")
        void shouldBeAutoConfiguration() {
            assertThat(IamXacmlPepAutoConfiguration.class
                    .getAnnotation(AutoConfiguration.class)).isNotNull();
        }
    }

    @Nested
    @DisplayName("Bean method annotations")
    class BeanMethods {

        @Test
        @DisplayName("Should have expressionAuthorizationManagerResolver bean with @ConditionalOnMissingBean")
        void shouldHaveResolverBean() throws Exception {
            Method method = IamXacmlPepAutoConfiguration.class
                    .getDeclaredMethod("expressionAuthorizationManagerResolver",
                            java.util.List.class,
                            org.springframework.security.access.expression.SecurityExpressionHandler.class);

            assertThat(method.getAnnotation(Bean.class)).isNotNull();
            assertThat(method.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
        }

        @Test
        @DisplayName("Should have customDynamicAuthorizationManager bean with @ConditionalOnMissingBean")
        void shouldHaveDynamicManagerBean() {
            boolean found = Arrays.stream(IamXacmlPepAutoConfiguration.class.getDeclaredMethods())
                    .filter(m -> m.getName().equals("customDynamicAuthorizationManager"))
                    .anyMatch(m -> m.getAnnotation(Bean.class) != null
                            && m.getAnnotation(ConditionalOnMissingBean.class) != null);

            assertThat(found).isTrue();
        }

        @Test
        @DisplayName("Should have protectableMethodAuthorizationManager bean with @ConditionalOnMissingBean")
        void shouldHaveProtectableManagerBean() {
            boolean found = Arrays.stream(IamXacmlPepAutoConfiguration.class.getDeclaredMethods())
                    .filter(m -> m.getName().equals("protectableMethodAuthorizationManager"))
                    .anyMatch(m -> m.getAnnotation(Bean.class) != null
                            && m.getAnnotation(ConditionalOnMissingBean.class) != null);

            assertThat(found).isTrue();
        }

        @Test
        @DisplayName("Should define exactly 3 bean methods")
        void shouldHaveThreeBeanMethods() {
            long beanCount = Arrays.stream(IamXacmlPepAutoConfiguration.class.getDeclaredMethods())
                    .filter(m -> m.getAnnotation(Bean.class) != null)
                    .count();

            assertThat(beanCount).isEqualTo(3);
        }
    }
}
