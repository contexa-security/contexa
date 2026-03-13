package io.contexa.contexaiam.security.xacml.pdp.translator;

import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.expression.spel.ast.MethodReference;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyTranslatorTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private GroupRepository groupRepository;

    @Mock
    private PermissionRepository permissionRepository;

    private PolicyTranslator policyTranslator;

    @BeforeEach
    void setUp() {
        // Translators list with a simple stub for method references
        SpelFunctionTranslator hasAuthorityTranslator = new SpelFunctionTranslator() {
            @Override
            public boolean supports(String functionName) {
                return "hasAuthority".equals(functionName) || "hasRole".equals(functionName);
            }

            @Override
            public ExpressionNode translate(String functionName, MethodReference node) {
                List<String> args = extractArguments(node);
                String argValue = args.isEmpty() ? "unknown" : args.get(0);
                if ("hasRole".equals(functionName)) {
                    return new TerminalNode("Has role: " + argValue, "ROLE_" + argValue, false);
                }
                return new TerminalNode("Has authority: " + argValue, argValue, false);
            }
        };

        policyTranslator = new PolicyTranslator(roleRepository, groupRepository, permissionRepository, List.of(hasAuthorityTranslator));
    }

    @Nested
    @DisplayName("translatePolicyToString")
    class TranslatePolicyToStringTest {

        @Test
        @DisplayName("Should return no-rules message for null policy")
        void shouldReturnNoRulesForNullPolicy() {
            String result = policyTranslator.translatePolicyToString(null);

            assertThat(result).isEqualTo("Policy with no defined rules.");
        }

        @Test
        @DisplayName("Should return no-rules message for policy with empty rules")
        void shouldReturnNoRulesForEmptyRules() {
            Policy policy = mock(Policy.class);
            doReturn(Collections.emptySet()).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).isEqualTo("Policy with no defined rules.");
        }

        @Test
        @DisplayName("Should return no-conditions message for rule with null conditions")
        void shouldReturnNoConditionsForNullConditions() {
            PolicyRule rule = mock(PolicyRule.class);
            doReturn(null).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).isEqualTo("(No defined conditions)");
        }
    }

    @Nested
    @DisplayName("SpEL expression translation")
    class SpelTranslationTest {

        @Test
        @DisplayName("Should translate AND operator")
        void shouldTranslateAndOperator() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("true and false");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).contains("and");
        }

        @Test
        @DisplayName("Should translate OR operator")
        void shouldTranslateOrOperator() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("true or false");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).contains("or");
        }

        @Test
        @DisplayName("Should translate NOT operator")
        void shouldTranslateNotOperator() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("!true");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).contains("NOT");
        }

        @Test
        @DisplayName("Should translate permitAll identifier")
        void shouldTranslatePermitAll() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("permitAll");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            // SpEL parses "permitAll" as PropertyOrFieldReference, not Identifier
            // so walkAndDescribe falls through to node.toStringAST() returning "permitAll"
            assertThat(result).contains("permitAll");
        }

        @Test
        @DisplayName("Should translate denyAll identifier")
        void shouldTranslateDenyAll() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("denyAll");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            // SpEL parses "denyAll" as PropertyOrFieldReference, not Identifier
            assertThat(result).contains("denyAll");
        }

        @Test
        @DisplayName("Should return original expression for invalid SpEL")
        void shouldReturnOriginalForInvalidSpel() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("{{invalid SpEL}}");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).contains("{{invalid SpEL}}");
        }

        @Test
        @DisplayName("Should translate comparison operators")
        void shouldTranslateComparisonOperators() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("1 == 1");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            String result = policyTranslator.translatePolicyToString(policy);

            assertThat(result).contains("equals");
        }
    }

    @Nested
    @DisplayName("parsePolicy")
    class ParsePolicyTest {

        @Test
        @DisplayName("Should return terminal node for null policy")
        void shouldReturnTerminalNodeForNullPolicy() {
            ExpressionNode result = policyTranslator.parsePolicy(null);

            assertThat(result).isInstanceOf(TerminalNode.class);
            assertThat(result.getConditionDescription()).isEqualTo("No defined rules");
        }

        @Test
        @DisplayName("Should return terminal node for empty rules")
        void shouldReturnTerminalNodeForEmptyRules() {
            Policy policy = mock(Policy.class);
            doReturn(Collections.emptySet()).when(policy).getRules();

            ExpressionNode result = policyTranslator.parsePolicy(policy);

            assertThat(result).isInstanceOf(TerminalNode.class);
            assertThat(result.getConditionDescription()).isEqualTo("No defined rules");
        }

        @Test
        @DisplayName("Should parse single rule with single condition")
        void shouldParseSingleRuleWithSingleCondition() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("permitAll");

            PolicyRule rule = mock(PolicyRule.class);
            doReturn(Set.of(condition)).when(rule).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(Set.of(rule)).when(policy).getRules();

            ExpressionNode result = policyTranslator.parsePolicy(policy);

            // SpEL parses "permitAll" as PropertyOrFieldReference, not Identifier
            // so walk() falls through to TerminalNode(node.toStringAST()) = "permitAll"
            assertThat(result.getConditionDescription()).isEqualTo("permitAll");
        }

        @Test
        @DisplayName("Should wrap multiple rules in OR logical node")
        void shouldWrapMultipleRulesInOrNode() {
            PolicyCondition cond1 = mock(PolicyCondition.class);
            when(cond1.getExpression()).thenReturn("permitAll");
            PolicyRule rule1 = mock(PolicyRule.class);
            doReturn(Set.of(cond1)).when(rule1).getConditions();

            PolicyCondition cond2 = mock(PolicyCondition.class);
            when(cond2.getExpression()).thenReturn("denyAll");
            PolicyRule rule2 = mock(PolicyRule.class);
            doReturn(Set.of(cond2)).when(rule2).getConditions();

            Policy policy = mock(Policy.class);
            doReturn(new LinkedHashSet<>(List.of(rule1, rule2))).when(policy).getRules();

            ExpressionNode result = policyTranslator.parsePolicy(policy);

            assertThat(result).isInstanceOf(LogicalNode.class);
            assertThat(result.getConditionDescription()).contains("OR");
        }
    }

    @Nested
    @DisplayName("parseCondition")
    class ParseConditionTest {

        @Test
        @DisplayName("Should return terminal node for unparseable expression")
        void shouldReturnTerminalForUnparseableExpression() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("{{broken}}");

            ExpressionNode result = policyTranslator.parseCondition(condition);

            assertThat(result).isInstanceOf(TerminalNode.class);
            assertThat(result.getConditionDescription()).isEqualTo("{{broken}}");
        }

        @Test
        @DisplayName("Should parse permitAll as terminal node")
        void shouldParsePermitAllAsTerminal() {
            PolicyCondition condition = mock(PolicyCondition.class);
            when(condition.getExpression()).thenReturn("permitAll");

            ExpressionNode result = policyTranslator.parseCondition(condition);

            // SpEL parses "permitAll" as PropertyOrFieldReference, not Identifier
            assertThat(result.getConditionDescription()).isEqualTo("permitAll");
        }
    }
}
