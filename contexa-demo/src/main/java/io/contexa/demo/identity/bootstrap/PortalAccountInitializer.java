package io.contexa.demo.identity.bootstrap;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.identity.repository.AccountRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Profile("portal")
public class PortalAccountInitializer implements ApplicationRunner {

    private final AccountRepository accounts;
    private final PasswordEncoder encoder;
    private final LabProperties properties;

    public PortalAccountInitializer(AccountRepository accounts, PasswordEncoder encoder, LabProperties properties) {
        this.accounts = accounts;
        this.encoder = encoder;
        this.properties = properties;
    }

    public void run(ApplicationArguments args) {
        if (properties.accountPassword() == null || properties.accountPassword().isBlank()) {
            return;
        }
        accounts.seedPortalAccount("admin", "운영자", encoder.encode(properties.accountPassword()),
                List.of("ROLE_ADMIN", "ROLE_USER"));
        accounts.seedPortalAccount("user", "참여자", encoder.encode(properties.accountPassword()), List.of("ROLE_USER"));
    }
}
