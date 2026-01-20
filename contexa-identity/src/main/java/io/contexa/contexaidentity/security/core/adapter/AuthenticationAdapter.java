package io.contexa.contexaidentity.security.core.adapter;

import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;


public interface AuthenticationAdapter {

    
    String getId();

    
    int getOrder();

    
    void apply(HttpSecurity http, List<AuthenticationStepConfig> steps, StateConfig state) throws Exception;
}

