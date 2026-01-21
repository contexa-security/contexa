package io.contexa.contexaiam.security.xacml.pip.resolver;

import org.springframework.security.core.GrantedAuthority;
import java.util.Set;

public interface SubjectAuthorityResolver {
    
    boolean supports(String subjectType);

    Set<GrantedAuthority> resolveAuthorities(Long subjectId);
}
