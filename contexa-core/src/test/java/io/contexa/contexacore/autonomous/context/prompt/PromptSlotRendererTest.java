package io.contexa.contexacore.autonomous.context.prompt;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class PromptSlotRendererTest {

    private final PromptSlotRenderer renderer = new PromptSlotRenderer();

    @Test
    void rendersSlotAsLegacyLabelValueLine() {
        PromptSlot slot = PromptSlot.line("DeviceBrowser", "Chrome", "Chrome");

        assertThat(renderer.renderLine(slot)).isEqualTo("DeviceBrowser: Chrome\n");
    }

    @Test
    void skipsBlankRenderedValues() {
        PromptSlot slot = PromptSlot.line("DeviceBrowser", "", "");

        assertThat(renderer.renderLine(slot)).isEmpty();
    }

    @Test
    void rendersSlotListWithoutChangingLineFormat() {
        List<PromptSlot> slots = List.of(
                PromptSlot.line("ActionFamily", "READ", "READ"),
                PromptSlot.line("ResourceId", "resource-001", "resource-001"));

        assertThat(renderer.render(slots))
                .isEqualTo("""
                        ActionFamily: READ
                        ResourceId: resource-001
                        """);
    }

    @Test
    void slotPlanBindsContractFieldsToRuntimeSlot() {
        PromptSlotPlan plan = new PromptSlotPlan(
                "user.current_request.action_family",
                "RESOURCE AND ACTION CONTEXT",
                "ActionFamily",
                "canonical.label.ActionFamily",
                "PromptContextComposer",
                "P0_REQUIRED",
                "PROTECT");

        PromptSlot slot = plan.bind("READ", "READ", "runtime value");

        assertThat(slot.slotKey()).isEqualTo("user.current_request.action_family");
        assertThat(slot.section()).isEqualTo("RESOURCE AND ACTION CONTEXT");
        assertThat(slot.label()).isEqualTo("ActionFamily");
        assertThat(slot.sourceValue()).isEqualTo("READ");
        assertThat(slot.renderedValue()).isEqualTo("READ");
        assertThat(slot.narrative()).isEqualTo("runtime value");
        assertThat(slot.priority()).isEqualTo("P0_REQUIRED");
    }

    @Test
    void slotPlanCacheReusesPlanWithoutCachingRuntimeValue() {
        PromptSlotPlan contractPlan = new PromptSlotPlan(
                "runtime.resource.action",
                "RESOURCE AND ACTION CONTEXT",
                "ActionFamily",
                "canonical.label.ActionFamily",
                "PromptContextComposer.composeResourceSection",
                "P0_REQUIRED",
                "PROTECT");
        PromptSlotPlanCache cache = new PromptSlotPlanCache((section, label) -> contractPlan);

        PromptSlot first = cache.planFor("RESOURCE AND ACTION CONTEXT", "ActionFamily").bind("READ", "READ", null);
        PromptSlot second = cache.planFor("RESOURCE AND ACTION CONTEXT", "ActionFamily").bind("DELETE", "DELETE", null);

        assertThat(cache.cachedPlanCount()).isEqualTo(1);
        assertThat(first.slotKey()).isEqualTo("runtime.resource.action");
        assertThat(first.label()).isEqualTo(second.label());
        assertThat(first.sourceValue()).isEqualTo("READ");
        assertThat(second.sourceValue()).isEqualTo("DELETE");
        assertThat(first.renderedValue()).isEqualTo("READ");
        assertThat(second.renderedValue()).isEqualTo("DELETE");
    }

    @Test
    void slotPlanCacheInvalidatesWhenProviderContractScopeChanges() {
        class ScopedProvider implements PromptSlotPlanProvider {
            private String scope = "contract-v1:prompt-v1";
            private final AtomicInteger loads = new AtomicInteger();

            @Override
            public PromptSlotPlan planFor(String sectionKey, String labelKey) {
                loads.incrementAndGet();
                return new PromptSlotPlan(
                        "slot." + scope,
                        sectionKey,
                        labelKey,
                        "canonical." + labelKey,
                        "PromptContextComposer",
                        "P0_REQUIRED",
                        "PROTECT");
            }

            @Override
            public String cacheScopeKey() {
                return scope;
            }
        }
        ScopedProvider provider = new ScopedProvider();
        PromptSlotPlanCache cache = new PromptSlotPlanCache(provider);

        PromptSlotPlan first = cache.planFor("RESOURCE AND ACTION CONTEXT", "ActionFamily");
        PromptSlotPlan cached = cache.planFor("RESOURCE AND ACTION CONTEXT", "ActionFamily");
        provider.scope = "contract-v2:prompt-v1";
        PromptSlotPlan refreshed = cache.planFor("RESOURCE AND ACTION CONTEXT", "ActionFamily");

        assertThat(first.slotKey()).isEqualTo("slot.contract-v1:prompt-v1");
        assertThat(cached).isSameAs(first);
        assertThat(refreshed.slotKey()).isEqualTo("slot.contract-v2:prompt-v1");
        assertThat(provider.loads).hasValue(2);
        assertThat(cache.cachedPlanCount()).isEqualTo(2);
    }

    @Test
    void defaultSlotPlanCacheDoesNotGenerateSyntheticContractKeys() {
        PromptSlotPlanCache cache = new PromptSlotPlanCache();

        PromptSlot slot = cache.planFor("RESOURCE AND ACTION CONTEXT", "ActionFamily")
                .bind("READ", "READ", null);

        assertThat(slot.slotKey()).isNull();
        assertThat(slot.section()).isEqualTo("RESOURCE AND ACTION CONTEXT");
        assertThat(slot.label()).isEqualTo("ActionFamily");
    }
}
