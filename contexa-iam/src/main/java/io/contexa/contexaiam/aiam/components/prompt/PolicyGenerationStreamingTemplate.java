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
import io.contexa.contexacore.std.components.prompt.AbstractStreamingPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptDocuments;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptDrawing;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionPin;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Streaming template for policy generation: the analysis in natural language first, then the policy as JSON between
 * the streaming markers. It shares the JSON schema of {@link PolicyGenerationTemplate}. Every sentence of the prompt is
 * the version's (plan 3.11): the version the resolver chooses for the prompt, else the product document
 * {@code prompt-versions/PolicyGenerationStreaming}. The code fills in the requirements, the items, the data, the
 * reference and the markers.
 */
public class PolicyGenerationStreamingTemplate extends AbstractStreamingPromptTemplate implements VersionedPrompt {

    /** The prompt key, the template key the prompt is called by. */
    public static final String PROMPT = "PolicyGenerationStreaming";
    /** The product releases this build ships, the latest last. */
    public static final List<String> RELEASES = List.of("2026.11.17");

    private static final ProductPromptDocuments DOCUMENTS =
            new ProductPromptDocuments(PolicyGenerationStreamingTemplate.class, PROMPT, RELEASES);
    /** The default descriptor of the template, the version of the call in place of its bundle version. */
    private static final PromptGovernanceDescriptor DESCRIPTOR =
            PromptGovernanceSupport.buildVersionedPromptDescriptor(PROMPT, PolicyGenerationStreamingTemplate.class);
    private static final Map<String, String> MARKERS = Map.of(
            "start", StreamingProtocol.JSON_START_MARKER,
            "end", StreamingProtocol.JSON_END_MARKER);

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
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return PromptDrawing.system(version(request), AssembledPrompt.JUDGMENT, Set.of(), MARKERS);
    }

    @Override
    protected String streamingInstructions(AIRequest<? extends DomainContext> request) {
        return PromptDrawing.system(version(request), VersionedTemplateDrawing.OUTPUT, Set.of(), MARKERS);
    }

    @Override
    protected String contextHeading(AIRequest<? extends DomainContext> request) {
        return VersionedTemplateDrawing.item(version(request), "structure-intro", "context-heading");
    }

    @Override
    protected String getJsonSchemaExample(AIRequest<? extends DomainContext> request) {
        return PromptDrawing.system(version(request), VersionedTemplateDrawing.FORMAT, Set.of(), MARKERS);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        AssembledPrompt version = version(request);
        PolicyGenerationItem.AvailableItems availableItems =
                request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);
        String iamDataContext = request.getParameter("iamDataContext", String.class);
        return user(version, naturalQuery(request, version), availableItems, iamDataContext, contextInfo);
    }

    private static String user(AssembledPrompt version, String naturalQuery,
                               PolicyGenerationItem.AvailableItems availableItems, String iamDataContext,
                               String contextInfo) {
        String reference = contextInfo != null && !contextInfo.isBlank()
                ? "\n" + VersionedTemplateDrawing.item(version, "request", "reference") + "\n" + contextInfo + "\n"
                : "";
        String systemContext = iamDataContext != null && !iamDataContext.isBlank()
                ? "\n" + VersionedTemplateDrawing.item(version, "request", "system-context") + "\n" + iamDataContext + "\n"
                : "";
        return PromptDrawing.user(version, Set.of(), Map.of(
                "query", String.valueOf(naturalQuery),
                "items", VersionedTemplateDrawing.availableItems(version, "request", availableItems),
                "system-context", systemContext,
                "reference", reference,
                "start", StreamingProtocol.JSON_START_MARKER,
                "end", StreamingProtocol.JSON_END_MARKER));
    }

    /**
     * Extracts the natural language query from the request: the parameter, else the request's context, else the
     * version's sentence that none was given.
     *
     * @param request the AI request
     * @return the natural language query or a default message
     */
    public String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        return naturalQuery(request, version(request));
    }

    private static String naturalQuery(AIRequest<? extends DomainContext> request, AssembledPrompt version) {
        String naturalQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalQuery != null) {
            return naturalQuery;
        }
        return request.getContext() != null ? request.getContext().toString()
                : VersionedTemplateDrawing.item(version, "request", "missing");
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
        String system = pin.with(version, () -> generateSystemPrompt(null, null));
        return new Example(system, user(version, "Let team managers read the documents of their team", items,
                "Roles: Team Manager, Document Handler", null));
    }
}
