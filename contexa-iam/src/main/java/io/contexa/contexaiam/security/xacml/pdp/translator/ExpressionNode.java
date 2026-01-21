package io.contexa.contexaiam.security.xacml.pdp.translator;

import java.util.Set;

public interface ExpressionNode {

    Set<String> getRequiredAuthorities();

    boolean requiresAuthentication();

    String getConditionDescription();
}