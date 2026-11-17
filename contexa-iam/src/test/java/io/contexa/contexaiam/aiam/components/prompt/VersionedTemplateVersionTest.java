/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-7: a version an organization made of each IAM prompt is what a call of that prompt draws once the resolver
 * chooses it: its changed part, its added part and the precedence sentence are in the prompt, its deleted part is
 * not, and the call's descriptor names the version. A request draws one version throughout, and a version cannot
 * change a part Contexa fixed.
 */
class VersionedTemplateVersionTest {

    private static final String PRECEDENCE = "Some parts of this text were written by your organization.";
    private final PromptAssembler assembler = new PromptAssembler();
    private final PromptVersionDocumentReader reader = new PromptVersionDocumentReader();

    private AssembledPrompt version(VersionedPrompt prompt, String body) {
        return assembler.apply(prompt.product(),
                reader.read("prompt: " + prompt.prompt() + "\nbasedOn: v1.0\ntitle: Ours\n" + body));
    }

    /** The versions of a database whose resolver chooses the given name, and whose store keeps the version under it. */
    private static PromptVersionInUse chosen(String prompt, AtomicReference<String> name, Map<String, AssembledPrompt> store) {
        return new PromptVersionInUse(() -> (context, subject) -> prompt.equals(context.promptKey())
                ? new PromptBundleSelection(name.get(), PromptBundleSelectionSource.REGISTRY) : PromptBundleSelection.none(),
                () -> (asked, version) -> prompt.equals(asked) ? Optional.ofNullable(store.get(version)) : Optional.empty());
    }

    @Test
    void theResourceNamingCallDrawsTheChosenVersion() {
        ResourceNamingTemplate template = new ResourceNamingTemplate();
        AssembledPrompt two = version(template, """
                system:
                  - key: role
                    text: |
                      You name the resources of the finance department in the words its staff use.
                  - key: org-glossary
                    add-after: naming-rules
                    title: Our glossary
                    text: |
                      A ledger is called a book; a payout is called a transfer.
                """);
        template.setPromptVersions(chosen(ResourceNamingTemplate.PROMPT, new AtomicReference<>("v2.0"), Map.of("v2.0", two)));
        AIRequest<? extends DomainContext> request = VersionedTemplateGoldenTest.request(new ResourceNamingContext(),
                Map.of("identifiers", List.of("/api/ledger")), null);

        String system = template.generateSystemPrompt(request, null);
        String user = template.generateUserPrompt(request, null);

        assertThat(system).contains("You name the resources of the finance department", PRECEDENCE,
                "Our glossary:\nA ledger is called a book").doesNotContain("You are a resource naming specialist AI");
        assertThat(user).contains("identifier: /api/ledger");
        assertThat(template.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v2.0");
        assertThat(template.getPromptGovernanceDescriptor().changeSummary()).contains(two.contentHash());
    }

    @Test
    void thePolicyGenerationCallDrawsTheChosenVersion() {
        PolicyGenerationTemplate template = new PolicyGenerationTemplate();
        AssembledPrompt two = version(template, """
                system:
                  - key: rules-methods
                    delete: true
                  - key: rules-guidance
                    text: |
                      - Never grant a role write access to the payroll ledger
                """);
        template.setPromptVersions(chosen(PolicyGenerationTemplate.PROMPT, new AtomicReference<>("v2.0"), Map.of("v2.0", two)));
        AIRequest<? extends DomainContext> request = VersionedTemplateGoldenTest.request(null, Map.of(), "Let managers read");

        String system = template.generateSystemPrompt(request, null);

        assertThat(system).contains("- Never grant a role write access to the payroll ledger", PRECEDENCE)
                .doesNotContain("Based on the target resource HTTP method", "principle of least privilege");
        assertThat(template.generateUserPrompt(request, null)).contains("[Natural Language Requirements]\nLet managers read");
        assertThat(template.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v2.0");
    }

    @Test
    void theStreamingPolicyGenerationCallDrawsTheChosenVersion() {
        PolicyGenerationStreamingTemplate template = new PolicyGenerationStreamingTemplate();
        AssembledPrompt two = version(template, """
                system:
                  - key: scope
                    text: |
                      Generate the access policies of the treasury team from what its leads ask for.
                """);
        template.setPromptVersions(chosen(PolicyGenerationStreamingTemplate.PROMPT, new AtomicReference<>("v3.0"),
                Map.of("v3.0", two)));
        AIRequest<? extends DomainContext> request = VersionedTemplateGoldenTest.request(null,
                Map.of("naturalLanguageQuery", "Let treasury leads approve"), null);

        String system = template.generateSystemPrompt(request, "metadata");

        assertThat(system).contains("Generate the access policies of the treasury team", PRECEDENCE,
                "===JSON_START===", "**Context Information:**\nmetadata").doesNotContain("Role assignment and permission mapping");
        assertThat(template.generateUserPrompt(request, null)).contains("\"Let treasury leads approve\"", "===JSON_END===");
        assertThat(template.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v3.0");
    }

    @Test
    void theConditionTemplateCallDrawsTheChosenVersion() {
        ConditionTemplatePromptTemplate template = new ConditionTemplatePromptTemplate();
        AssembledPrompt two = version(template, """
                system:
                  - key: specific-role
                    text: |
                      You write the access conditions of the payment services' methods.
                """);
        template.setPromptVersions(chosen(ConditionTemplatePromptTemplate.PROMPT, new AtomicReference<>("v2.0"),
                Map.of("v2.0", two)));
        AIRequest<? extends DomainContext> request = VersionedTemplateGoldenTest.request(
                new ConditionTemplateContext("specific", "/api/pay", "pay(Long id)"),
                Map.of("methodSignatures", List.of("pay(Long id)")), null);

        assertThat(template.generateSystemPrompt(request, null)).contains("You write the access conditions of the payment",
                PRECEDENCE, "        <rules>").doesNotContain("You are a specialized AI that analyzes Java method");
        assertThat(template.generateUserPrompt(request, null)).contains("1. pay(Long id)", "**all 1 items**");
        assertThat(template.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v2.0");
    }

    /** Plan 3.4: a label moved while a request is drawn does not mix two versions in its prompt. */
    @Test
    void aRequestDrawsOneVersionThroughout() {
        ResourceNamingTemplate template = new ResourceNamingTemplate();
        AssembledPrompt two = version(template, """
                user:
                  - key: org-note
                    add-after: confirm
                    title: Note
                    text: |
                      The resources belong to the finance department.
                """);
        AtomicReference<String> label = new AtomicReference<>("v2.0");
        template.setPromptVersions(chosen(ResourceNamingTemplate.PROMPT, label, Map.of("v2.0", two)));
        AIRequest<? extends DomainContext> first = VersionedTemplateGoldenTest.request(new ResourceNamingContext(),
                Map.of("identifiers", List.of("/api/ledger")), null);

        template.generateSystemPrompt(first, null);
        label.set("v1.0");
        String sameRequest = template.generateUserPrompt(first, null);
        String nextRequest = template.generateUserPrompt(VersionedTemplateGoldenTest.request(new ResourceNamingContext(),
                Map.of("identifiers", List.of("/api/ledger")), null), null);

        assertThat(sameRequest).contains("The resources belong to the finance department.");
        assertThat(nextRequest).doesNotContain("The resources belong to the finance department.");
    }

    /** Plan 3.5: the parts Contexa fixed (the output contract, the schema) cannot be changed by a version. */
    @Test
    void aVersionCannotChangeAFixedPart() {
        for (VersionedPrompt prompt : List.<VersionedPrompt>of(new ResourceNamingTemplate(), new PolicyGenerationTemplate(),
                new PolicyGenerationStreamingTemplate(), new ConditionTemplatePromptTemplate())) {
            String fixed = prompt.product().system().stream().filter(part -> part.isLocked() && part.when() == null)
                    .findFirst().orElseThrow().key();
            PromptAssembler.Check check = assembler.check(prompt.product(), reader.read("prompt: " + prompt.prompt()
                    + "\nbasedOn: v1.0\ntitle: Ours\nsystem:\n  - key: " + fixed + "\n    text: |\n      Changed.\n"), null);

            assertThat(check.problems()).as(prompt.prompt() + " " + fixed).extracting(PromptVersionProblem::code)
                    .contains(PromptVersionProblem.Code.LOCKED_PART);
        }
    }

    /** Without the console's database the product document is drawn, named by its release. */
    @Test
    void withoutADatabaseTheProductDocumentIsDrawn() {
        ResourceNamingTemplate template = new ResourceNamingTemplate();

        assertThat(template.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("2026.11.17-v1.0");
        assertThat(template.product().release()).isEqualTo("2026.11.17-v1.0");
        assertThat(template.productReleases()).hasSize(1);
    }
}
