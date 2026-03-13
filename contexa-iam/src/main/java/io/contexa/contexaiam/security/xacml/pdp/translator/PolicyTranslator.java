package io.contexa.contexaiam.security.xacml.pdp.translator;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.dto.EntitlementDto;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.ast.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@RequiredArgsConstructor
public class PolicyTranslator {

    private final SpelExpressionParser expressionParser = new SpelExpressionParser();
    private final RoleRepository roleRepository;
    private final GroupRepository groupRepository;
    private final PermissionRepository permissionRepository;
    private final List<SpelFunctionTranslator> translators;

    private record AnalysisResult(List<String> subjectDescriptions, String subjectType, List<String> actionDescriptions, List<String> conditionDescriptions) {}

    public String translatePolicyToString(Policy policy) {
        if (policy == null || policy.getRules() == null || policy.getRules().isEmpty()) {
            return "Policy with no defined rules.";
        }

        return policy.getRules().stream()
                .map(this::translateRuleToString)
                .collect(Collectors.joining(" or "));
    }

    private String translateRuleToString(PolicyRule rule) {
        if (rule.getConditions() == null || rule.getConditions().isEmpty()) {
            return "(No defined conditions)";
        }

        String conditionsDescription = rule.getConditions().stream()
                .map(this::translateConditionToString)
                .collect(Collectors.joining(" and "));

        return "(" + conditionsDescription + ")";
    }

    private String translateConditionToString(PolicyCondition condition) {
        try {
            Expression expression = expressionParser.parseExpression(condition.getExpression());
            SpelNode ast = ((SpelExpression) expression).getAST();
            return walkAndDescribe(ast);
        } catch (Exception e) {
            log.warn("Error occurred during SpEL translation: {}. Returning original expression as-is.", condition.getExpression(), e);
            return condition.getExpression(); 
        }
    }

    private String walkAndDescribe(SpelNode node) {
        
        if (node instanceof OpAnd) {
            return String.format("(%s and %s)", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        }
        if (node instanceof OpOr) {
            return String.format("(%s or %s)", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        }
        if (node instanceof OperatorNot) {
            return String.format("NOT (%s)", walkAndDescribe(node.getChild(0)));
        }

        if (node instanceof OpEQ) return String.format("%s equals %s", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        if (node instanceof OpNE) return String.format("%s not equals %s", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        if (node instanceof OpGT) return String.format("%s greater than %s", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        if (node instanceof OpGE) return String.format("%s greater than or equal to %s", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        if (node instanceof OpLT) return String.format("%s less than %s", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));
        if (node instanceof OpLE) return String.format("%s less than or equal to %s", walkAndDescribe(node.getChild(0)), walkAndDescribe(node.getChild(1)));

        if (node instanceof MethodReference methodRef) {
            String methodName = methodRef.getName();
            for (SpelFunctionTranslator translator : translators) {
                if (translator.supports(methodName)) {
                    
                    return translator.translate(methodName, methodRef).getConditionDescription();
                }
            }
        }

        if (node instanceof Identifier) {
            String identifier = node.toStringAST();
            if ("permitAll".equalsIgnoreCase(identifier)) return "All access permitted";
            if ("denyAll".equalsIgnoreCase(identifier)) return "All access denied";
        }

        return node.toStringAST();
    }

    public Stream<EntitlementDto> translate(Policy policy, String resourceName) {
        return policy.getRules().stream().map(rule -> {
            List<ExpressionNode> conditionNodes = rule.getConditions().stream()
                    .map(this::parseCondition)
                    .collect(Collectors.toList());
            ExpressionNode rootNode = (conditionNodes.size() == 1) ? conditionNodes.get(0) : new LogicalNode("AND", conditionNodes);

            AnalysisResult analysis = analyzeNode(rootNode);

            return new EntitlementDto(
                    policy.getId(),
                    String.join(", ", analysis.subjectDescriptions),
                    analysis.subjectType,
                    resourceName,
                    analysis.actionDescriptions,
                    analysis.conditionDescriptions
            );
        });
    }

    private AnalysisResult analyzeNode(ExpressionNode rootNode) {
        List<String> subjectDescs = new ArrayList<>();
        List<String> actionDescs = new ArrayList<>();
        List<String> conditionDescs = new ArrayList<>();
        String subjectType = "N/A";

        Set<String> authorities = rootNode.getRequiredAuthorities();
        for (String auth : authorities) {
            if (auth.startsWith("ROLE_")) {
                
                String roleName = auth.substring(5);
                
                String friendlyName = roleRepository.findByRoleName(roleName).map(r -> r.getRoleDesc()).orElse(roleName);
                subjectDescs.add(friendlyName);
                subjectType = "Role";
            } else if (auth.startsWith("GROUP_")) {
                
                Long groupId = Long.parseLong(auth.substring(6));
                
                String friendlyName = groupRepository.findById(groupId).map(g -> g.getName()).orElse("ID: " + groupId);
                subjectDescs.add(friendlyName);
                subjectType = "Group";
            } else {
                
                String friendlyName = permissionRepository.findByName(auth).map(p -> p.getDescription()).orElse(auth);
                actionDescs.add(friendlyName);
            }
        }

        if (rootNode.requiresAuthentication() && subjectDescs.isEmpty()) {
            subjectDescs.add("Authenticated user");
            subjectType = "Authentication status";
        }

        conditionDescs.add(rootNode.getConditionDescription());

        return new AnalysisResult(subjectDescs, subjectType, actionDescs, conditionDescs);
    }

    public ExpressionNode parseCondition(PolicyCondition condition) {
        try {
            Expression expression = expressionParser.parseExpression(condition.getExpression());
            SpelNode ast = ((SpelExpression) expression).getAST();
            return walk(ast);
        } catch (Exception e) {
            log.warn("Could not parse SpEL expression: {}. Treating as opaque condition.", condition.getExpression(), e);
            return new TerminalNode(condition.getExpression()); 
        }
    }

    public ExpressionNode parsePolicy(Policy policy) {
        if (policy == null || policy.getRules() == null || policy.getRules().isEmpty()) {
            return new TerminalNode("No defined rules");
        }

        List<ExpressionNode> ruleNodes = policy.getRules().stream()
                .map(this::parseRule)
                .collect(Collectors.toList());

        return (ruleNodes.size() == 1) ? ruleNodes.getFirst() : new LogicalNode("OR", ruleNodes);
    }

    private ExpressionNode parseRule(PolicyRule rule) {
        if (rule.getConditions() == null || rule.getConditions().isEmpty()) {
            return new TerminalNode("No defined conditions");
        }
        List<ExpressionNode> conditionNodes = rule.getConditions().stream()
                .map(this::parseCondition)
                .collect(Collectors.toList());

        return (conditionNodes.size() == 1) ? conditionNodes.getFirst() : new LogicalNode("AND", conditionNodes);
    }

    private ExpressionNode walk(SpelNode node) {
        
        if (node instanceof OpAnd) return new LogicalNode("AND", getChildren(node));
        if (node instanceof OpOr) return new LogicalNode("OR", getChildren(node));
        if (node instanceof OperatorNot) return new LogicalNode("NOT", getChildren(node));

        if (node instanceof MethodReference methodRef) {
            String methodName = methodRef.getName();

            for (SpelFunctionTranslator translator : translators) {
                if (translator.supports(methodName)) {
                    return translator.translate(methodName, methodRef);
                }
            }
        }

        if (node instanceof Identifier) {
            String identifier = node.toStringAST();
            if ("permitAll".equalsIgnoreCase(identifier)) return new TerminalNode("Permit all users", false);
            if ("denyAll".equalsIgnoreCase(identifier)) return new TerminalNode("Deny all users", false);
        }

        return new TerminalNode(node.toStringAST());
    }

    private List<ExpressionNode> getChildren(SpelNode node) {
        List<ExpressionNode> children = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) {
            children.add(walk(node.getChild(i)));
        }
        return children;
    }

    private List<String> getMethodArguments(SpelNode node) {
        List<String> args = new ArrayList<>();
        for (int i = 0; i < node.getChildCount(); i++) {
            SpelNode child = node.getChild(i);
            if (child instanceof StringLiteral) {
                args.add(((StringLiteral) child).getLiteralValue().getValue().toString());
            } else if (child instanceof CompoundExpression) { 
                for (int j = 0; j < child.getChildCount(); j++) {
                    if (child.getChild(j) instanceof StringLiteral) {
                        args.add(((StringLiteral) child.getChild(j)).getLiteralValue().getValue().toString());
                    }
                }
            }
        }
        return args;
    }
}