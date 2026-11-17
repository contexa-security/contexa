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

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.AbstractBasePromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptDocuments;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptDrawing;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionPin;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The template of the condition templates: three universal conditions, or one specific condition per method
 * signature. Every sentence of the prompt is the version's (plan 3.11): the version the resolver chooses for the
 * prompt, else the product document {@code prompt-versions/ConditionTemplate}. The code fills in the method signatures,
 * their count and the reference context.
 */
public class ConditionTemplatePromptTemplate extends AbstractBasePromptTemplate implements VersionedPrompt {

    /** The prompt key, the template key the prompt is called by. */
    public static final String PROMPT = "ConditionTemplate";
    /** The product releases this build ships, the latest last. */
    public static final List<String> RELEASES = List.of("2026.11.17");

    private static final String UNIVERSAL = "universal";
    private static final String SPECIFIC = "specific";
    private static final ProductPromptDocuments DOCUMENTS =
            new ProductPromptDocuments(ConditionTemplatePromptTemplate.class, PROMPT, RELEASES);
    /** The default descriptor of the template, the version of the call in place of its bundle version. */
    private static final PromptGovernanceDescriptor DESCRIPTOR =
            PromptGovernanceSupport.buildDefaultDescriptor(PROMPT, ConditionTemplatePromptTemplate.class);

    private final PromptVersionPin pin = new PromptVersionPin();
    private PromptVersionInUse versions = PromptVersionInUse.productOnly();

    /** The versions the template reads; without them it draws the product document. */
    public void setPromptVersions(PromptVersionInUse versions) {
        this.versions = Objects.requireNonNull(versions, "versions");
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType(PROMPT);
    }

    @Override
    public PromptGovernanceDescriptor getPromptGovernanceDescriptor() {
        return pin.last(this::choose).describe(DESCRIPTOR);
    }

    @Override
    public Class<?> getAIGenerationType() {
        return Map.class;
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return system(version(request), templateType(request), systemMetadata);
    }

    private static String system(AssembledPrompt version, String templateType, String systemMetadata) {
        Set<String> conditions = Set.of(SPECIFIC.equals(templateType) ? SPECIFIC : UNIVERSAL);
        return VersionedTemplateDrawing.jsonSystem(version, conditions, Map.of(), systemMetadata);
    }

    @Override
    @SuppressWarnings("unchecked")
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        AssembledPrompt version = version(request);
        if (SPECIFIC.equals(templateType(request))) {
            List<String> methodSignatures = request.getParameter("methodSignatures", List.class);
            if (methodSignatures != null && !methodSignatures.isEmpty()) {
                return batch(version, methodSignatures, contextInfo);
            }
            return single(version, contextInfo != null ? contextInfo : "");
        }
        return PromptDrawing.user(version, Set.of(UNIVERSAL), Map.of());
    }

    /** One condition for each of the signatures, the reference context before them when there is one. */
    private static String batch(AssembledPrompt version, List<String> methodSignatures, String contextInfo) {
        StringBuilder methods = new StringBuilder();
        for (int index = 0; index < methodSignatures.size(); index++) {
            methods.append(index + 1).append(". ").append(methodSignatures.get(index)).append('\n');
        }
        boolean withContext = contextInfo != null && !contextInfo.trim().isEmpty();
        return VersionedTemplateDrawing.withoutLastBreak(PromptDrawing.user(version,
                withContext ? Set.of("batch", "batch-context") : Set.of("batch"),
                Map.of("context", withContext ? contextInfo : "", "count", String.valueOf(methodSignatures.size()),
                        "methods", methods.toString())));
    }

    private static String single(AssembledPrompt version, String methodSignature) {
        return PromptDrawing.user(version, Set.of("single"), Map.of("signature", methodSignature));
    }

    private String templateType(AIRequest<? extends DomainContext> request) {
        if (request != null && isContextType(request, ConditionTemplateContext.class)) {
            ConditionTemplateContext context = (ConditionTemplateContext) request.getContext();
            return context.getTemplateType();
        }
        String type = request != null ? request.getParameter("templateType", String.class) : null;
        return type != null ? type : UNIVERSAL;
    }

    private AssembledPrompt version(AIRequest<? extends DomainContext> request) {
        return pin.of(request, this::choose).version();
    }

    private PromptVersionInUse.Choice choose() {
        return versions.choose(PROMPT, DOCUMENTS.product(), null);
    }

    // ----- the prompt's versions (plan 3.11) -----

    @Override
    public String prompt() {
        return PROMPT;
    }

    @Override
    public List<ProductPromptRelease> productReleases() {
        return DOCUMENTS.releases();
    }

    @Override
    public AssembledPrompt product() {
        return DOCUMENTS.product();
    }

    @Override
    public PromptGovernanceDescriptor registryDescriptor() {
        return DESCRIPTOR;
    }

    @Override
    public Example example(AssembledPrompt version) {
        return new Example(system(version, SPECIFIC, null),
                batch(version, List.of("getGroup(Long id)", "createGroup(Group group)"), null));
    }
}
