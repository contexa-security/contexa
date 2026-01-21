package io.contexa.contexaiam.security.xacml.pip.context;

import io.contexa.contexacommon.entity.Users;
import org.springframework.security.core.Authentication;

import java.util.Map;

public record AuthorizationContext(
        Authentication subject,    
        Users subjectEntity,    
        ResourceDetails resource,    
        String action,             
        EnvironmentDetails environment, 
        Map<String, Object> attributes ) { }
