package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R1b-7 (P3 extra 35): the fact accuracy check compares the REQUEST lines and the coverage line whole, as the render's
 * own value functions draw them from the sealed sources, not only their heads. A part the render may take from a source
 * the package does not seal is matched only by the value the sealed sources give; a line that differs only there is
 * left unchecked with why, never pointed at.
 */
class PromptInspectionWholeLineTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);
    private static final List<String> LABELS =
            List.of("Subject", "Roles", "Permissions", "Action", "ResourceClass", "Network", "Device", "Coverage");

    @Test
    void theWholeLinesTheRenderDrawsFromTheSealedSourcesAreMatched() {
        InspectionGolden.Render render = rich(context -> {
        });

        for (String label : LABELS) {
            assertThat(InspectionGolden.hasLine(render.userPrompt(), label + ": ")).as(label).isTrue();
        }
        PromptInspectionCheckResult check = check(render.userPrompt(), render);
        assertThat(check.findings()).filteredOn(finding -> LABELS.contains(finding.entry())).isEmpty();
    }

    @Test
    void aDetailOtherThanTheSealedOneIsPointedAtWithTheWholeSealedLine() {
        InspectionGolden.Render render = rich(context -> {
        });
        Map<String, String[]> changes = new LinkedHashMap<>();
        changes.put("Subject", new String[]{"dept PLM-OPS", "dept FINANCE"});
        changes.put("Roles", new String[]{"scope tags project:GB-500", "scope tags project:GB-501"});
        changes.put("Permissions", new String[]{"source host (SECURITY_CONTEXT)", "source host (TOKEN)"});
        changes.put("Action", new String[]{"(declared)", "(inferred from method name)"});
        changes.put("ResourceClass", new String[]{"sensitivity CRITICAL", "sensitivity LOW"});
        changes.put("Network", new String[]{"Seoul", "Busan"});
        changes.put("Device", new String[]{"OS version 11", "OS version 10"});
        changes.put("Coverage", new String[]{"hints bind the project roles", "hints none"});

        for (Map.Entry<String, String[]> change : changes.entrySet()) {
            String label = change.getKey();
            String line = InspectionGolden.lineStarting(render.userPrompt(), label + ": ");
            assertThat(line).as(label).contains(change.getValue()[0]);
            String changed = line.replace(change.getValue()[0], change.getValue()[1]);

            List<PromptInspectionFinding> found = check(render.userPrompt().replace(line, changed), render).findings()
                    .stream().filter(finding -> label.equals(finding.entry())).toList();
            assertThat(found).as(label).singleElement().satisfies(finding -> {
                assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH);
                assertThat(finding.expected()).isEqualTo(valueOf(line));
                assertThat(finding.actual()).isEqualTo(valueOf(changed));
            });
        }
    }

    @Test
    void aPartTheRenderTakesFromASourceThePackageDoesNotSealIsLeftUncheckedNotPointedAt() {
        // The account age counts to the event time when the request time is not sealed.
        InspectionGolden.Render unsealedTime = rich(context -> context.setRequestObservedAt(null));
        String subject = InspectionGolden.lineStarting(unsealedTime.userPrompt(), "Subject: ");
        assertThat(subject).contains("account ").doesNotContain("account age not known");
        assertThat(on(check(unsealedTime.userPrompt(), unsealedTime), "Subject")).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
            assertThat(finding.sourceRef()).isEqualTo("canonicalContext.requestObservedAt");
        });
        // Another part of the same line is still compared.
        String otherDept = subject.replace("dept PLM-OPS", "dept FINANCE");
        assertThat(on(check(unsealedTime.userPrompt().replace(subject, otherDept), unsealedTime), "Subject"))
                .singleElement().satisfies(finding ->
                        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.MISMATCH));

        // Without a sealed path template, the render's template may come from a URL template the package does not
        // seal: the one the sealed request facts give is matched, another is left unchecked.
        InspectionGolden.Render noTemplate = rich(context -> context.getResource().setPathFamily(null));
        String action = InspectionGolden.lineStarting(noTemplate.userPrompt(), "Action: ");
        assertThat(action).contains("template ");
        assertThat(on(check(noTemplate.userPrompt(), noTemplate), "Action")).isEmpty();
        String otherTemplate = action.replaceFirst("template [^,)]+", "template /api/other/{key}");
        assertThat(on(check(noTemplate.userPrompt().replace(action, otherTemplate), noTemplate), "Action"))
                .singleElement().satisfies(finding -> {
                    assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                    assertThat(finding.sourceRef()).isEqualTo("canonicalContext.resource.pathFamily");
                });
    }

    /**
     * The band and the protected method the render takes from the request's metadata are sealed as the request facts
     * (the assembler's client address and protected method): compared when the facts are sealed, left unchecked when
     * they are not. Whether the host declared the device new is not sealed at all.
     */
    @Test
    void whatTheRenderTakesFromTheRequestsMetadataIsComparedOnlyWhereItIsSealed() {
        InspectionGolden.Render render = rich(context -> {
            context.getLocation().setIpBand(null);
            context.getResource().setResourceId("io.example.Other#call");
            context.getSession().setNewDevice(true);
        });
        String network = InspectionGolden.lineStarting(render.userPrompt(), "Network: ");
        String action = InspectionGolden.lineStarting(render.userPrompt(), "Action: ");
        assertThat(network).contains("/24");
        assertThat(action).contains("method ").doesNotContain("method Other.call");
        PromptInspectionCheckResult sealedFacts = check(render.userPrompt(), render);
        assertThat(on(sealedFacts, "Network")).isEmpty();
        assertThat(on(sealedFacts, "Action")).isEmpty();

        SealedEvidencePackage withoutFacts = render.sealed(render.userPrompt());
        withoutFacts.setRequestFactsJson(null);
        PromptInspectionCheckResult unsealedFacts = INSPECTOR.inspect(withoutFacts).checks().get(0);
        assertThat(on(unsealedFacts, "Network")).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
            assertThat(finding.sourceRef()).isEqualTo("canonicalContext.location.ipBand");
        });
        assertThat(on(unsealedFacts, "Action")).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
            assertThat(finding.sourceRef()).isEqualTo("requestFactsJson.protectableMethod");
        });

        String device = InspectionGolden.lineStarting(render.userPrompt(), "Device: ");
        assertThat(on(sealedFacts, "Device")).isEmpty();
        String declared = device.contains("not seen in past records")
                ? device.replace("not seen in past records", "new device per host")
                : device.replace("WINDOWS (", "WINDOWS (new device per host, ");
        assertThat(declared).isNotEqualTo(device);
        assertThat(on(check(render.userPrompt().replace(device, declared), render), "Device")).singleElement()
                .satisfies(finding -> {
                    assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                    assertThat(finding.sourceRef()).isEqualTo("canonicalContext.session.newDevice");
                });
    }

    /** The real packages the showcase engine sealed under this bundle state the whole lines their sealed sources draw. */
    @Test
    void theShowcaseEnginesPackagesStateTheWholeLinesTheirSealedSourcesDraw() {
        for (SealedEvidencePackage sealed : InspectionGolden.showcaseSealed()) {
            PromptInspectionCheckResult check = INSPECTOR.inspect(sealed).checks().get(0);
            assertThat(check.findings()).as(sealed.getPackageId())
                    .filteredOn(finding -> LABELS.contains(finding.entry())).isEmpty();
            assertThat(check.matched()).as(sealed.getPackageId()).isPositive();
        }
    }

    /**
     * A golden render whose sealed context holds every detail the REQUEST lines and the coverage line draw: the
     * subject's department and position with the account's creation, the roles and permissions with scope tags, the
     * privileged flow and the bridge's authorization source, the action's source, the resource's sensitivity and flags,
     * the location's city, country and ASN, the device's system details and the bridge's hints.
     */
    private static InspectionGolden.Render rich(Consumer<CanonicalSecurityContext> more) {
        InspectionGolden.Render base = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Subject: ")
                && InspectionGolden.hasLine(text, "Action: ") && InspectionGolden.hasLine(text, "Coverage: "));
        return InspectionGolden.renderWith(base, context -> {
            context.setRequestObservedAt(Instant.parse("2026-10-12T03:17:00Z"));
            CanonicalSecurityContext.Actor actor = context.getActor();
            actor.setDepartment("PLM-OPS");
            actor.setPosition("Engineer");
            actor.setAccountCreatedAt("2026-01-01T00:00:00Z");
            CanonicalSecurityContext.Authorization authorization = context.getAuthorization() != null
                    ? context.getAuthorization() : new CanonicalSecurityContext.Authorization();
            authorization.setEffectiveRoles(new ArrayList<>(List.of("ROLE_ENGINEER", "ROLE_ADMIN")));
            authorization.setEffectivePermissions(new ArrayList<>(List.of("document:read", "document:export")));
            authorization.setScopeTags(new ArrayList<>(List.of("project:GB-500")));
            authorization.setPrivileged(true);
            context.setAuthorization(authorization);
            context.getBridge().setAuthorizationSource("SECURITY_CONTEXT");
            context.getBridge().setRemediationHints(new ArrayList<>(List.of("bind the project roles")));
            CanonicalSecurityContext.Resource resource = context.getResource();
            resource.setActionFamily("EXPORT");
            resource.setActionFamilySource("host");
            resource.setHttpMethod("POST");
            resource.setPathFamily("/api/projects/{projectKey}/exports");
            resource.setRequestPath("/api/projects/GB-500/exports");
            resource.setResourceClass("CRITICAL");
            resource.setSensitivity("CRITICAL");
            resource.setSensitiveResource(true);
            resource.setExportSensitive(true);
            if (context.getSession() == null) {
                context.setSession(new CanonicalSecurityContext.Session());
            }
            context.getSession().setClientIp("10.40.12.7");
            if (context.getLocation() == null) {
                context.setLocation(new CanonicalSecurityContext.Location());
            }
            context.getLocation().setIpBand("10.40.12.0/24");
            context.getLocation().setNetworkZone("CORPORATE");
            context.getLocation().setCity("Seoul");
            context.getLocation().setCountry("KR");
            context.getLocation().setAsn("AS4766");
            if (context.getDevice() == null) {
                context.setDevice(new CanonicalSecurityContext.Device());
            }
            context.getDevice().setBrowser("Chrome");
            context.getDevice().setBrowserVersion("140");
            context.getDevice().setOs("WINDOWS");
            context.getDevice().setOsVersion("11");
            context.getDevice().setLanguage("ko-KR");
            context.getDevice().setScreenResolution("1920x1080");
            context.getDevice().setFingerprintMatch(true);
            more.accept(context);
        });
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render) {
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed(userPrompt));
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    private static List<PromptInspectionFinding> on(PromptInspectionCheckResult check, String label) {
        return check.findings().stream().filter(finding -> label.equals(finding.entry())).toList();
    }

    /** The value of a drawn line, without its fact id and label. */
    private static String valueOf(String line) {
        String bare = InspectionGolden.bare(line);
        return bare.substring(bare.indexOf(": ") + 2);
    }
}
