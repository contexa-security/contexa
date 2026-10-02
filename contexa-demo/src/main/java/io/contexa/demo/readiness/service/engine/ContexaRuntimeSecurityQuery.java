package io.contexa.demo.readiness.service.engine;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.demo.readiness.dto.RuntimeMode;
import io.contexa.demo.readiness.service.RuntimeSecurityQuery;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("contexa")
public class ContexaRuntimeSecurityQuery implements RuntimeSecurityQuery {

    private final ObjectProvider<SecurityZeroTrustProperties> properties;

    public ContexaRuntimeSecurityQuery(ObjectProvider<SecurityZeroTrustProperties> properties) {
        this.properties = properties;
    }

    @Override
    public RuntimeMode inspect() {
        SecurityZeroTrustProperties current = properties.getIfUnique();
        if (current == null || current.getMode() == null) {
            return new RuntimeMode(false, "UNAVAILABLE", false, false);
        }
        return new RuntimeMode(current.isEnabled(), current.getMode().name(),
                current.allowsLlmAnalysis(), current.isEnforcementEnabled());
    }
}
