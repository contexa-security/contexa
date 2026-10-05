package io.contexa.showcase.portal.template;

import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Keeps a current template for every protagonist whose scenarios clone one (plan P1 "automate re-learning", ADR-23
 * template lifetime): when the versions in force change or no template was learned yet, it learns a new template
 * through {@link TemplateLearner}, one employee at a time. An employee whose attempt is still learning is left alone,
 * and one whose attempt failed waits an hour before the next try so a broken engine does not spend the budget in a loop.
 * Live runs that need a template are refused while none is current (LiveGate), so visitors see a pause rather than a
 * run on a stale template.
 */
public class TemplateMaintainer implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(TemplateMaintainer.class);

    static final Duration LEARNING_WINDOW = Duration.ofMinutes(45);
    static final Duration FAILURE_BACKOFF = Duration.ofHours(1);

    /** Learns one employee's template; {@link TemplateLearner#learn} in production. */
    @FunctionalInterface
    public interface Learner {
        String learn(String employeeKey) throws IOException;
    }

    /** What the last check found per employee: CURRENT, LEARNED, LEARNING, WAITING_AFTER_FAILURE or FAILED. */
    public record Check(Instant at, Map<String, String> employees) {
    }

    private final List<String> employees;
    private final TemplateCurrency currency;
    private final TemplateStore templates;
    private final Learner learner;
    private final Clock clock;
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "showcase-template-maintainer");
        thread.setDaemon(true);
        return thread;
    });
    private volatile Check last;

    public TemplateMaintainer(ScenarioCatalog scenarios, TemplateCurrency currency, TemplateStore templates,
                              Learner learner, Clock clock) {
        this.employees = scenarios.all().stream().filter(ScenarioDefinition::template)
                .map(ScenarioDefinition::protagonist).distinct().sorted().toList();
        this.currency = currency;
        this.templates = templates;
        this.learner = learner;
        this.clock = clock;
    }

    /** Checks 30 seconds after start and then every 10 minutes. */
    public void start() {
        executor.scheduleWithFixedDelay(this::check, 30, 600, TimeUnit.SECONDS);
    }

    public List<String> employees() {
        return employees;
    }

    public Check last() {
        return last;
    }

    /** One pass over the employees; each one that has no current template is learned now. */
    public Check check() {
        Map<String, String> found = new TreeMap<>();
        for (String employee : employees) {
            try {
                found.put(employee, maintain(employee));
            } catch (IOException | RuntimeException e) {
                log.error("Template maintenance failed: employee={}", employee, e);
                found.put(employee, "FAILED");
            }
        }
        last = new Check(clock.instant(), found);
        return last;
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }

    private String maintain(String employee) throws IOException {
        if (currency.current(employee).isPresent()) {
            return "CURRENT";
        }
        Instant now = clock.instant();
        if (templates.learningSince(employee, now.minus(LEARNING_WINDOW))) {
            return "LEARNING";
        }
        if (templates.failedSince(employee, now.minus(FAILURE_BACKOFF))) {
            return "WAITING_AFTER_FAILURE";
        }
        String templateId = learner.learn(employee);
        if (templateId == null) {
            log.error("No template could be learned: employee={}", employee);
            return "FAILED";
        }
        return "LEARNED";
    }
}
