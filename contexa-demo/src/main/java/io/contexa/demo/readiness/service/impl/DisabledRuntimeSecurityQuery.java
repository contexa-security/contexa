package io.contexa.demo.readiness.service.impl;

import io.contexa.demo.readiness.dto.RuntimeMode;
import io.contexa.demo.readiness.service.RuntimeSecurityQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!contexa")
public class DisabledRuntimeSecurityQuery implements RuntimeSecurityQuery {

    @Override
    public RuntimeMode inspect() {
        return new RuntimeMode(false, "DISABLED", false, false);
    }
}
