package io.contexa.contexaiam.security.xacml.pdp.translator;

import lombok.Getter;

import java.util.Collections;
import java.util.Set;

@Getter
public class TerminalNode implements ExpressionNode {

    private final String description;
    private final String authority;
    private final boolean authenticationRequired; 

    public TerminalNode(String description, String authority, boolean authenticationRequired) {
        this.description = description;
        this.authority = authority;
        this.authenticationRequired = authenticationRequired;
    }

    public TerminalNode(String description, boolean authenticationRequired) {
        this(description, null, authenticationRequired);
    }

    public TerminalNode(String description) {
        this(description, null, false); 
    }

    @Override
    public Set<String> getRequiredAuthorities() {
        return authority != null ? Set.of(authority) : Collections.emptySet();
    }

    @Override
    public boolean requiresAuthentication() {
        return this.authenticationRequired;
    }

    @Override
    public String getConditionDescription() {
        return description;
    }
}

