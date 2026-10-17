package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fact accuracy check on the REQUEST lines whose values list or combine sealed fields: the roles and permissions
 * (as sets), the action family, method and path template, the target's label and category, and the device name.
 */
class PromptInspectionRequestFactsTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);

    @Test
    void rolesAndPermissionsAreComparedAsTheSealedSets() {
        InspectionGolden.Render render = base();
        CanonicalSecurityContext context = copy(render.used());
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization() != null
                ? context.getAuthorization() : new CanonicalSecurityContext.Authorization();
        authorization.setEffectiveRoles(List.of("ROLE_ADMIN", "ROLE_ENGINEER"));
        authorization.setEffectivePermissions(List.of("document:read", "document:export"));
        context.setAuthorization(authorization);

        // R1b-7: the line is compared whole, with the host source the sealed bridge names.
        String kept = withRequestLines(render, "Roles: ROLE_ADMIN, ROLE_ENGINEER; source host (SECURITY_CONTEXT)",
                "Permissions: document:export, document:read; source host (SECURITY_CONTEXT)");
        assertThat(mismatches(check(kept, render, context))).isEmpty();

        String broken = withRequestLines(render, "Roles: ROLE_ADMIN, ROLE_ROOT; source host",
                "Permissions: document:read; source host");
        List<PromptInspectionFinding> findings = mismatches(check(broken, render, context));
        assertThat(findings).extracting(PromptInspectionFinding::entry).containsExactlyInAnyOrder("Roles", "Permissions");
        assertThat(findings).extracting(PromptInspectionFinding::sourceRef).containsExactlyInAnyOrder(
                "canonicalContext.authorization.effectiveRoles", "canonicalContext.authorization.effectivePermissions");
    }

    @Test
    void theActionFamilyMethodAndTemplateAreComparedWithTheSealedResource() {
        // An export request, so the export template sealed below names the target its line states.
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Target: ")
                && InspectionGolden.hasLine(text, "Time: ") && lineStarting(text, "Action: ").contains("Action: EXPORT")
                && lineStarting(text, "Action: ").contains("/api/projects/{projectKey}/exports"));
        CanonicalSecurityContext context = copy(render.used());
        CanonicalSecurityContext.Resource resource = resource(context);
        resource.setActionFamily("EXPORT");
        resource.setActionFamilySource("host");
        resource.setHttpMethod("POST");
        resource.setPathFamily("/api/projects/{projectKey}/exports");
        String action = lineStarting(render.userPrompt(), "Action: ");
        // R1b-7: the line is compared whole, with the protected method the sealed request facts name.
        Matcher protectedMethod = Pattern.compile("method [^,)]+").matcher(action);
        assertThat(protectedMethod.find()).isTrue();

        String kept = render.userPrompt().replace(action, InspectionGolden.factIdOf(action)
                + "Action: EXPORT (declared) POST (template /api/projects/{projectKey}/exports, " + protectedMethod.group() + ")");
        assertThat(mismatches(check(kept, render, context))).isEmpty();

        String broken = render.userPrompt().replace(action,
                InspectionGolden.factIdOf(action) + "Action: READ (declared) GET (template /api/documents/{documentId})");
        PromptInspectionFinding finding = single(check(broken, render, context));
        assertThat(finding.entry()).isEqualTo("Action");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.resource.actionFamily");
        assertThat(finding.expected()).isEqualTo("EXPORT");
        assertThat(finding.actual()).isEqualTo("READ");
    }

    @Test
    void aMethodOtherThanTheSealedOneIsPointedAt() {
        InspectionGolden.Render render = base();
        CanonicalSecurityContext context = copy(render.used());
        CanonicalSecurityContext.Resource resource = resource(context);
        resource.setActionFamily("EXPORT");
        resource.setHttpMethod("POST");
        String action = lineStarting(render.userPrompt(), "Action: ");

        PromptInspectionFinding finding = single(check(render.userPrompt().replace(action, InspectionGolden.factIdOf(action) + "Action: EXPORT (declared) GET"),
                render, context));
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.resource.httpMethod");
        assertThat(finding.expected()).isEqualTo("POST");
    }

    /**
     * N-INJ-3: the target line names the business label only by where it is (its text is an UNTRUSTED TEXT line) and
     * states the sealed category; a line that states the label's text, or a label the sealed resource lacks, is
     * pointed at.
     */
    @Test
    void theTargetLabelAndCategoryAreComparedWithTheSealedResource() {
        InspectionGolden.Render render = InspectionGolden.renderWith(base(), context -> {
            resource(context).setBusinessLabel("Design exports");
            resource(context).setResourceCategory("ENGINEERING_DATA");
        });
        String target = lineStarting(render.userPrompt(), "Target: ");
        String head = InspectionGolden.bare(target).substring("Target: ".length()).split(" \\(")[0].split(", category ")[0];

        assertThat(InspectionGolden.bare(target))
                .isEqualTo("Target: " + head + " (business label in UNTRUSTED TEXT), category ENGINEERING_DATA");
        assertThat(mismatches(check(render.userPrompt(), render, render.used()))).isEmpty();

        String broken = render.userPrompt().replace(target, InspectionGolden.factIdOf(target) + "Target: " + head + " (Design exports), category ENGINEERING_DATA");
        PromptInspectionFinding finding = single(check(broken, render, render.used()));
        assertThat(finding.entry()).isEqualTo("Target");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.resource.businessLabel");
        assertThat(finding.expected()).isEqualTo("business label in UNTRUSTED TEXT");
        assertThat(finding.actual()).isEqualTo("Design exports");

        InspectionGolden.Render unlabelled = InspectionGolden.renderWith(base(), context -> {
            resource(context).setBusinessLabel(null);
            resource(context).setResourceCategory("ENGINEERING_DATA");
        });
        String drawn = lineStarting(unlabelled.userPrompt(), "Target: ");
        String claimed = unlabelled.userPrompt().replace(drawn, InspectionGolden.factIdOf(drawn) + "Target: " + head
                + " (business label in UNTRUSTED TEXT), category ENGINEERING_DATA");
        PromptInspectionFinding claim = single(check(claimed, unlabelled, unlabelled.used()));
        assertThat(claim.entry()).isEqualTo("Target");
        assertThat(claim.sourceRef()).isEqualTo("canonicalContext.resource.businessLabel");
    }

    /**
     * N-INJ-3 (R1b-2): the render draws the business label once, as an UNTRUSTED TEXT line trimmed as every untrusted
     * text is, and the inspector finds that line the sealed label.
     */
    @Test
    void theBusinessLabelIsDrawnOnceAsTheUntrustedTextTheInspectorExpects() {
        InspectionGolden.Render render = InspectionGolden.renderWith(base(),
                context -> resource(context).setBusinessLabel(" Design exports "));
        List<String> drawn = Arrays.stream(render.userPrompt().split("\n")).map(InspectionGolden::bare)
                .filter(line -> line.contains("Design exports")).toList();

        assertThat(drawn).hasSize(1);
        assertThat(drawn.get(0))
                .matches("UntrustedText\\d+: source=business label \\(host text\\); \"Design exports\"");
        String label = drawn.get(0).substring(0, drawn.get(0).indexOf(": "));
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
        assertThat(result.checks().get(0).findings())
                .filteredOn(finding -> label.equals(finding.entry()) || "Target".equals(finding.entry())).isEmpty();
    }

    @Test
    void aDeviceNameOtherThanTheSealedDeviceIsPointedAt() {
        // A device line without a comparison with past records is drawn by the sealed device alone.
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Device: ")
                && !lineStarting(text, "Device: ").contains("past records"));
        CanonicalSecurityContext context = copy(render.used());
        CanonicalSecurityContext.Device device = context.getDevice() != null
                ? context.getDevice() : new CanonicalSecurityContext.Device();
        device.setBrowser("Chrome");
        device.setBrowserVersion("140");
        device.setOs("WINDOWS");
        context.setDevice(device);
        String line = lineStarting(render.userPrompt(), "Device: ");

        assertThat(mismatches(check(render.userPrompt().replace(line, InspectionGolden.factIdOf(line) + "Device: Chrome/140 on WINDOWS"), render, context)))
                .isEmpty();
        PromptInspectionFinding finding = single(check(render.userPrompt().replace(line, InspectionGolden.factIdOf(line) + "Device: Firefox/120 on MAC"),
                render, context));
        assertThat(finding.entry()).isEqualTo("Device");
        assertThat(finding.expected()).isEqualTo("Chrome/140 on WINDOWS");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.device");
    }

    @Test
    void theSizeIsComparedWithTheSealedRequestedSize() {
        InspectionGolden.Render render = base();
        CanonicalSecurityContext context = copy(render.used());
        resource(context).setRequestedItems(4831);

        assertThat(mismatches(check(withLine(render, "Size: 4,831 items"), render, context))).isEmpty();
        PromptInspectionFinding finding = single(check(withLine(render, "Size: 4,830 items"), render, context));
        assertThat(finding.entry()).isEqualTo("Size");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.resource.requestedItems");
    }

    @Test
    void theNetworkAddressAndZoneAreComparedWithTheSealedSessionAndLocation() {
        InspectionGolden.Render render = base();
        CanonicalSecurityContext context = copy(render.used());
        if (context.getSession() == null) {
            context.setSession(new CanonicalSecurityContext.Session());
        }
        context.getSession().setClientIp("10.40.12.7");
        if (context.getLocation() == null) {
            context.setLocation(new CanonicalSecurityContext.Location());
        }
        context.getLocation().setNetworkZone("OFFICE");
        // R1b-7: the line is compared whole, with the band of the sealed location.
        String band = context.getLocation().getIpBand();
        assertThat(band).isNotBlank();

        assertThat(mismatches(check(withLine(render, "Network: 10.40.12.7 (" + band + ", zone OFFICE)"), render, context)))
                .isEmpty();
        PromptInspectionFinding address = single(check(withLine(render, "Network: 10.40.12.8 (zone OFFICE)"), render, context));
        assertThat(address.sourceRef()).isEqualTo("canonicalContext.session.clientIp");
        PromptInspectionFinding zone = single(check(withLine(render, "Network: 10.40.12.7 (zone REMOTE)"), render, context));
        assertThat(zone.sourceRef()).isEqualTo("canonicalContext.location.networkZone");
    }

    /**
     * R1b-2: the inspector expects what the render draws. The render of a golden case whose sealed context carries the
     * request time, the size, the target's label and category, the client address (padded) and the network zone is
     * inspected without a finding on those lines.
     */
    @Test
    void theDrawnLinesAreWhatTheInspectorExpects() {
        InspectionGolden.Render render = InspectionGolden.renderWith(base(), context -> {
            context.setRequestObservedAt(Instant.parse("2026-10-12T03:17:00Z"));
            CanonicalSecurityContext.Resource resource = resource(context);
            resource.setRequestedItems(4831);
            resource.setBusinessLabel(" Design exports ");
            resource.setResourceCategory("ENGINEERING_DATA");
            if (context.getSession() == null) {
                context.setSession(new CanonicalSecurityContext.Session());
            }
            context.getSession().setClientIp(" 10.40.12.7 ");
            if (context.getLocation() == null) {
                context.setLocation(new CanonicalSecurityContext.Location());
            }
            context.getLocation().setNetworkZone("OFFICE");
        });
        List<String> labels = List.of("Time", "Size", "Target", "Network");

        for (String label : labels) {
            assertThat(InspectionGolden.hasLine(render.userPrompt(), label + ": ")).as(label).isTrue();
        }
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
        assertThat(result.checks().get(0).findings().stream()
                .filter(finding -> "REQUEST".equals(finding.block()) && labels.contains(finding.entry())))
                .isEmpty();
    }

    /** The prompt with the line in place of the drawn line of its label, or after the Time line. */
    private static String withLine(InspectionGolden.Render render, String line) {
        String label = line.substring(0, line.indexOf(": ") + 2);
        String text = render.userPrompt();
        String existing = Arrays.stream(text.split("\n")).filter(drawn -> InspectionGolden.bare(drawn).startsWith(label))
                .findFirst().orElse(null);
        if (existing != null) {
            return text.replace(existing, InspectionGolden.factIdOf(existing) + line);
        }
        String time = lineStarting(text, "Time: ");
        return text.replace(time + "\n", time + "\n" + line + "\n");
    }

    private static InspectionGolden.Render base() {
        return InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Action: ") && InspectionGolden.hasLine(text, "Target: ")
                && InspectionGolden.hasLine(text, "Time: "));
    }

    private static CanonicalSecurityContext.Resource resource(CanonicalSecurityContext context) {
        if (context.getResource() == null) {
            context.setResource(new CanonicalSecurityContext.Resource());
        }
        return context.getResource();
    }

    /** The prompt with Roles and Permissions lines after the Time line (the line order is the contract check's). */
    private static String withRequestLines(InspectionGolden.Render render, String roles, String permissions) {
        String time = lineStarting(render.userPrompt(), "Time: ");
        String text = render.userPrompt();
        for (String drawn : List.of("Roles: ", "Permissions: ")) {
            String existing = Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(drawn)).findFirst().orElse(null);
            if (existing != null) {
                text = text.replace(existing + "\n", "");
            }
        }
        return text.replace(time + "\n", time + "\n" + roles + "\n" + permissions + "\n");
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render,
                                                     CanonicalSecurityContext context) {
        var sealed = render.sealed(userPrompt);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    private static CanonicalSecurityContext copy(CanonicalSecurityContext context) {
        return InspectionGolden.SERIALIZER.deserialize(InspectionGolden.SERIALIZER.serialize(context));
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).toList();
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        List<PromptInspectionFinding> mismatches = mismatches(check);
        assertThat(mismatches).hasSize(1);
        return mismatches.get(0);
    }

    private static String lineStarting(String text, String start) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(start)).findFirst().orElseThrow();
    }
}
