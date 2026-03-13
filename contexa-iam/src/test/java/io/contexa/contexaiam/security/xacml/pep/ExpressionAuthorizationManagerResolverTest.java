package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.ExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ExpressionAuthorizationManagerResolverTest {

    @Mock
    private SecurityExpressionHandler<RequestAuthorizationContext> customWebSecurityExpressionHandler;

    @Mock
    private ExpressionEvaluator customEvaluator;

    @Mock
    private AuthorizationManager<RequestAuthorizationContext> customManager;

    private ExpressionAuthorizationManagerResolver resolver;

    @Nested
    @DisplayName("Evaluator routing order")
    class RoutingOrderTest {

        @Test
        @DisplayName("Should use first evaluator that supports the expression")
        void shouldUseFirstSupportingEvaluator() {
            ExpressionEvaluator first = mock(ExpressionEvaluator.class);
            ExpressionEvaluator second = mock(ExpressionEvaluator.class);
            AuthorizationManager<RequestAuthorizationContext> firstManager = mock(AuthorizationManager.class);

            when(first.supports("someExpression")).thenReturn(true);
            when(first.createManager("someExpression")).thenReturn(firstManager);
            when(second.supports("someExpression")).thenReturn(true);

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(first, second), customWebSecurityExpressionHandler);

            AuthorizationManager<RequestAuthorizationContext> result = resolver.resolve("someExpression");

            assertThat(result).isSameAs(firstManager);
            verify(second, never()).createManager(any());
        }

        @Test
        @DisplayName("Should skip evaluators that do not support the expression")
        void shouldSkipNonSupportingEvaluators() {
            ExpressionEvaluator unsupported = mock(ExpressionEvaluator.class);
            ExpressionEvaluator supported = mock(ExpressionEvaluator.class);
            AuthorizationManager<RequestAuthorizationContext> manager = mock(AuthorizationManager.class);

            when(unsupported.supports("testExpr")).thenReturn(false);
            when(supported.supports("testExpr")).thenReturn(true);
            when(supported.createManager("testExpr")).thenReturn(manager);

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(unsupported, supported), customWebSecurityExpressionHandler);

            AuthorizationManager<RequestAuthorizationContext> result = resolver.resolve("testExpr");

            assertThat(result).isSameAs(manager);
            verify(unsupported, never()).createManager(any());
        }
    }

    @Nested
    @DisplayName("resolve method returns AuthorizationManager")
    class ResolveTest {

        @Test
        @DisplayName("Should return WebExpressionAuthorizationManager with custom handler for WebSpelExpressionEvaluator")
        void shouldReturnWebExpressionManagerForWebSpel() {
            WebSpelExpressionEvaluator webSpelEvaluator = new WebSpelExpressionEvaluator();
            // setExpressionHandler internally calls handler.getExpressionParser().parseExpression()
            when(customWebSecurityExpressionHandler.getExpressionParser())
                    .thenReturn(new SpelExpressionParser());

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(webSpelEvaluator), customWebSecurityExpressionHandler);

            AuthorizationManager<RequestAuthorizationContext> result = resolver.resolve("hasRole('ADMIN')");

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should use custom evaluator's createManager for non-WebSpel evaluators")
        void shouldUseCustomEvaluatorCreateManager() {
            when(customEvaluator.supports("customExpr")).thenReturn(true);
            when(customEvaluator.createManager("customExpr")).thenReturn(customManager);

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(customEvaluator), customWebSecurityExpressionHandler);

            AuthorizationManager<RequestAuthorizationContext> result = resolver.resolve("customExpr");

            assertThat(result).isSameAs(customManager);
            verify(customEvaluator).createManager("customExpr");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when no evaluator supports the expression")
        void shouldThrowWhenNoEvaluatorFound() {
            when(customEvaluator.supports("unsupported")).thenReturn(false);

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(customEvaluator), customWebSecurityExpressionHandler);

            assertThatThrownBy(() -> resolver.resolve("unsupported"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("unsupported");
        }
    }

    @Nested
    @DisplayName("Custom handler setting")
    class CustomHandlerTest {

        @Test
        @DisplayName("Should set custom expression handler on WebExpressionAuthorizationManager")
        void shouldSetCustomHandlerOnWebManager() {
            WebSpelExpressionEvaluator webSpelEvaluator = new WebSpelExpressionEvaluator();
            // setExpressionHandler internally calls handler.getExpressionParser().parseExpression()
            when(customWebSecurityExpressionHandler.getExpressionParser())
                    .thenReturn(new SpelExpressionParser());

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(webSpelEvaluator), customWebSecurityExpressionHandler);

            AuthorizationManager<RequestAuthorizationContext> result = resolver.resolve("isAuthenticated()");

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should not set custom handler for non-WebSpel evaluators")
        void shouldNotSetHandlerForNonWebSpel() {
            when(customEvaluator.supports("expr")).thenReturn(true);
            when(customEvaluator.createManager("expr")).thenReturn(customManager);

            resolver = new ExpressionAuthorizationManagerResolver(
                    List.of(customEvaluator), customWebSecurityExpressionHandler);

            AuthorizationManager<RequestAuthorizationContext> result = resolver.resolve("expr");

            // Custom evaluator path does not involve WebExpressionAuthorizationManager
            assertThat(result).isSameAs(customManager);
        }
    }
}
