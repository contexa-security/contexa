package io.contexa.contexaiam.security.xacml.pip.attribute;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;

import java.util.Map;


public interface AttributeInformationPoint {
    
    Map<String, Object> getAttributes(AuthorizationContext context);
}
