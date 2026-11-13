package io.contexa.contexaiam.admin.promptquality.official.state;

import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The state descriptors in the language of the screen. A catalog may hold its labels and next actions in one language
 * only (the enterprise catalog reads them from its table, seeded in Korean), and the prompt-quality APIs pass them on
 * as they are. Here the label and the next action of a state are the messages of the current locale named by its
 * dimension and code ({@value #PREFIX}DIMENSION.CODE.label and .nextAction); a state the messages do not name keeps
 * the catalog's text. Codes, tones, groups, orders and actions are not changed.
 */
public final class LocalizedPromptQualityStateCatalog implements PromptQualityStateCatalog {

    static final String PREFIX = "enterprise.pqa.stateCatalog.";

    private final PromptQualityStateCatalog delegate;
    private final Supplier<PromptQualityMessageResolver> messages;

    private LocalizedPromptQualityStateCatalog(PromptQualityStateCatalog delegate,
                                               Supplier<PromptQualityMessageResolver> messages) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.messages = Objects.requireNonNull(messages, "messages");
    }

    /** The catalog in the language of the screen; a catalog already so is returned as it is. */
    public static PromptQualityStateCatalog of(PromptQualityStateCatalog catalog,
                                               Supplier<PromptQualityMessageResolver> messages) {
        return catalog instanceof LocalizedPromptQualityStateCatalog ? catalog
                : new LocalizedPromptQualityStateCatalog(catalog, messages);
    }

    @Override
    public List<PromptQualityStateDescriptor> descriptors() {
        List<PromptQualityStateDescriptor> descriptors = delegate.descriptors();
        return descriptors == null ? null : descriptors.stream().map(this::localized).toList();
    }

    @Override
    public PromptQualityStateDescriptor describe(PromptQualityStateDimension dimension, String code) {
        return localized(delegate.describe(dimension, code));
    }

    @Override
    public PromptQualityStateDescriptor resourceRequestObservation(boolean evidenceObserved, boolean decisionRecorded) {
        return localized(delegate.resourceRequestObservation(evidenceObserved, decisionRecorded));
    }

    @Override
    public PromptQualityStateDescriptor runtimeEvidence(boolean sealed, boolean integrityValid, boolean warningSignals) {
        return localized(delegate.runtimeEvidence(sealed, integrityValid, warningSignals));
    }

    @Override
    public List<String> resourceOperationalActions(String operationalState, boolean promotable) {
        return delegate.resourceOperationalActions(operationalState, promotable);
    }

    private PromptQualityStateDescriptor localized(PromptQualityStateDescriptor descriptor) {
        PromptQualityMessageResolver resolver = descriptor == null ? null : messages.get();
        if (resolver == null) {
            return descriptor;
        }
        String key = PREFIX + descriptor.dimension() + "." + descriptor.code();
        String label = text(resolver, key + ".label", descriptor.label());
        String nextAction = text(resolver, key + ".nextAction", descriptor.nextAction());
        if (Objects.equals(label, descriptor.label()) && Objects.equals(nextAction, descriptor.nextAction())) {
            return descriptor;
        }
        return new PromptQualityStateDescriptor(descriptor.dimension(), descriptor.processStage(), descriptor.code(),
                label, descriptor.tone(), descriptor.aggregateGroup(), descriptor.allowedActions(), nextAction,
                descriptor.order());
    }

    private static String text(PromptQualityMessageResolver resolver, String key, String fallback) {
        String resolved = resolver.resolve(key);
        return !StringUtils.hasText(resolved) || key.equals(resolved) ? fallback : resolved;
    }
}
