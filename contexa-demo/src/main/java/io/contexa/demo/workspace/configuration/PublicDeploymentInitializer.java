package io.contexa.demo.workspace.configuration;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.entry.configuration.EntryProperties;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;

@Component
@Profile("public")
public class PublicDeploymentInitializer implements ApplicationRunner {

    private final LabProperties lab;
    private final EntryProperties entry;
    private final Environment environment;

    public PublicDeploymentInitializer(LabProperties lab, EntryProperties entry, Environment environment) {
        this.lab = lab;
        this.entry = entry;
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        List<URI> origins = List.of(URI.create(entry.portalUrl()), lab.endpoints().baseline(), lab.endpoints().contexa());
        String host = origins.get(0).getHost();
        if (host == null || origins.stream().anyMatch(origin -> !"https".equals(origin.getScheme())
                || !host.equals(origin.getHost()) || origin.getUserInfo() != null || origin.getQuery() != null
                || origin.getFragment() != null || !(origin.getPath().isEmpty() || "/".equals(origin.getPath())))) {
            throw new IllegalStateException("Public origins require HTTPS on one host with distinct role ports");
        }
        if (origins.stream().distinct().count() != 3 || !entry.secureCookie()
                || !environment.getProperty("server.ssl.enabled", Boolean.class, false)
                || !host.equals(environment.getRequiredProperty("LAB_RP_ID"))) {
            throw new IllegalStateException("Public TLS, role origins, cookie and RP configuration must agree");
        }
    }
}
