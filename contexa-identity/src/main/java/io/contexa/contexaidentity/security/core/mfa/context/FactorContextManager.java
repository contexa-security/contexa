package io.contexa.contexaidentity.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;


public interface FactorContextManager {
    
    FactorContext load(HttpServletRequest req);

    
    void save(FactorContext ctx, HttpServletRequest req);

    
    void clear(HttpServletRequest req);
}


