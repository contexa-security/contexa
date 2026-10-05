package io.contexa.showcase.business;

import io.contexa.showcase.business.company.CompanyInitializer;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

/**
 * Runs the company generation at startup when the workload owns the business database
 * (showcase.company.generate-on-start=true); otherwise does nothing.
 */
public class CompanyGenerationRunner implements ApplicationRunner {

    private final CompanyInitializer initializer;

    public CompanyGenerationRunner(CompanyInitializer initializer) {
        this.initializer = initializer;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (initializer != null) {
            initializer.run(args);
        }
    }
}
