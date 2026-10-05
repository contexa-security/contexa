package io.contexa.showcase.business.company;

import io.contexa.showcase.business.work.WorkDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.time.Clock;
import java.time.LocalDate;
import java.util.Optional;

/**
 * Generates the virtual company once, on the first start of a workload that owns the business database. Several
 * plain instances start together, so generation runs under a transaction-scoped advisory lock and only the first
 * one writes. A stored company generated with another seed or generator version is reported, never replaced.
 */
public class CompanyInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(CompanyInitializer.class);

    /** Arbitrary constant key of the advisory lock that serializes generation across instances. */
    private static final long GENERATION_LOCK = 0x5348_4f57_4341_5345L;

    private final WorkDatabase database;
    private final CompanyRepository repository;
    private final long seed;
    private final LocalDate configuredAnchor;
    private final Clock clock;

    public CompanyInitializer(WorkDatabase database, CompanyRepository repository, long seed, LocalDate configuredAnchor,
                              Clock clock) {
        this.database = database;
        this.repository = repository;
        this.seed = seed;
        this.configuredAnchor = configuredAnchor;
        this.clock = clock;
    }

    @Override
    public void run(ApplicationArguments args) {
        database.transactions().executeWithoutResult(status -> {
            database.jdbc().query("select pg_advisory_xact_lock(:key)",
                    new MapSqlParameterSource("key", GENERATION_LOCK), rs -> {
                    });
            Optional<CompanyRepository.Generation> stored = repository.generation();
            if (stored.isPresent()) {
                CompanyRepository.Generation generation = stored.get();
                if (generation.seed() != seed || !CompanyGenerator.VERSION.equals(generation.generatorVersion())) {
                    log.error("Stored company differs from the configuration: storedSeed={}, storedVersion={}, "
                                    + "configuredSeed={}, configuredVersion={}", generation.seed(),
                            generation.generatorVersion(), seed, CompanyGenerator.VERSION);
                }
                return;
            }
            LocalDate anchor = configuredAnchor != null ? configuredAnchor : CompanyCalendar.anchorFor(LocalDate.now(clock));
            repository.write(new CompanyGenerator().generate(seed, anchor));
        });
    }
}
