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
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Non-streaming template for policy generation.
 * <p>
 * It shares the JSON schema of {@link PolicyGenerationStreamingTemplate}, so a client reads the same structure in
 * either mode. Every sentence of the prompt is the version's (plan 3.11): the version the resolver chooses for the
 * prompt, else the product document {@code prompt-versions/PolicyGeneration}. The code fills in the requirements, the
 * items a policy may use and the data.
 * </p>
 *
 * @see AbstractBasePromptTemplate
 * @see PolicyGenerationStreamingTemplate
 */
public class PolicyGenerationTemplate extends AbstractBasePromptTemplate implements VersionedPrompt {

    /** The prompt key, the template key the prompt is called by. */
    public static final String PROMPT = "PolicyGeneration";
    /** The product releases this build ships, the latest last. */
    public static final List<String> RELEASES = List.of("2026.11.17");

    private static final ProductPromptDocuments DOCUMENTS =
            new ProductPromptDocuments(PolicyGenerationTemplate.class, PROMPT, RELEASES);
    /** The default descriptor of the template, the version of the call in place of its bundle version. */
    private static final PromptGovernanceDescriptor DESCRIPTOR =
            PromptGovernanceSupport.buildVersionedPromptDescriptor(PROMPT, PolicyGenerationTemplate.class);

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
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return VersionedTemplateDrawing.jsonSystem(version(request), Set.of(), Map.of(), systemMetadata);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        AssembledPrompt version = version(request);
        String naturalQuery = extractNaturalQuery(request);
        if (naturalQuery == null || naturalQuery.equals("Natural language query was not provided")) {
            naturalQuery = VersionedTemplateDrawing.item(version, "requirements", "missing");
        }
        PolicyGenerationItem.AvailableItems availableItems =
                request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);
        return user(version, naturalQuery, availableItems, data(version, request, contextInfo));
    }

    private static String user(AssembledPrompt version, String naturalQuery,
                               PolicyGenerationItem.AvailableItems availableItems, String data) {
        return PromptDrawing.user(version, Set.of(), Map.of(
                "query", naturalQuery,
                "items", VersionedTemplateDrawing.availableItems(version, "available-items", availableItems),
                // A request without data has drawn the word null here since the first release (defect K53).
                "data", String.valueOf(data)));
    }

    /** The IAM data of the request, and the similar query patterns after it under the version's separator. */
    private String data(AssembledPrompt version, AIRequest<? extends DomainContext> request, String contextInfo) {
        String iamDataContext = request.getParameter(IAM_DATA_CONTEXT_PARAM, String.class);
        if (iamDataContext != null && !iamDataContext.isBlank() && contextInfo != null && !contextInfo.isBlank()) {
            return iamDataContext + "\n\n" + VersionedTemplateDrawing.item(version, "data", "rag-separator") + "\n"
                    + contextInfo;
        }
        if (iamDataContext != null && !iamDataContext.isBlank()) {
            return iamDataContext;
        }
        return contextInfo;
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
        PolicyGenerationItem.AvailableItems items = new PolicyGenerationItem.AvailableItems(
                List.of(new PolicyGenerationItem.RoleItem(101L, "Team Manager", null)),
                List.of(new PolicyGenerationItem.PermissionItem(201L, "Read documents", null, "URL", "/api/documents",
                        "GET")),
                List.of(new PolicyGenerationItem.ConditionItem(301L, "Within Business Hours", null, true)));
        return new Example(VersionedTemplateDrawing.jsonSystem(version, Set.of(), Map.of(), null),
                user(version, "Let team managers read the documents of their team during business hours", items,
                        "Roles: Team Manager, Document Handler"));
    }
}
