package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * What Contexa knows about an employee before the visitor acts as them (docs/showcase/화면설계서.md scene 1): the
 * engine's own learned baseline of the run principal's template (hours, weekdays, networks, devices, how many requests
 * it learned) and the work that was sent to teach it (operations, projects, export sizes). Every number is counted
 * from these two sources and nothing else; the screen names the source of each.
 */
public final class BaselineCard {

    /**
     * @param hours    learned requests per hour of the day, index 0 to 23 (engine baseline)
     * @param weekdays learned requests per weekday, index 0 = Monday (engine baseline)
     * @param networks network bands the engine learned as usual
     * @param devices  operating systems and browsers the engine learned as usual
     */
    public record Learned(int requests, List<Integer> hours, List<Integer> weekdays, List<String> networks,
                          List<String> devices) {
    }

    /**
     * @param projects       requests per project of the work sent to teach the engine
     * @param exportItemsMin smallest export of that work, null without exports
     * @param exportItemsMax largest export of that work, null without exports
     */
    public record Taught(int reads, int downloads, int exports, Integer exportItemsMin, Integer exportItemsMax,
                         Map<String, Integer> projects, Instant from, Instant to) {
    }

    /**
     * @param requests every request sent to teach the template, in order (template_step with its activity)
     * @param sent     how many requests were sent to teach it
     * @param allowed  how many of them the engine allowed; the baseline learned {@code learned.requests()}
     * @param hours    the hour lists the engine received in the latest real decision made from the template; null
     *                 before any
     * @param capturedAt when the template's snapshot of the engine's baseline was taken (the source mark's recorded
     *                   time); null when the snapshot does not say
     */
    public record View(String employeeKey, String displayName, String department, String templateId,
                       Learned learned, Taught taught, List<BaselineEvidence.LearnedRequest> requests, int sent,
                       int allowed, BaselineEvidence.EngineHours hours, String capturedAt) {

        View withHours(BaselineEvidence.EngineHours latest) {
            return new View(employeeKey, displayName, department, templateId, learned, taught, requests, sent,
                    allowed, latest, capturedAt);
        }
    }

    private BaselineCard() {
    }

    /**
     * @param templateId the template the run principals of this employee are cloned from
     * @param snapshot   the template snapshot; its {@code userBaseline} is the engine's baseline as JSON text
     * @param employee   the employee profile of the work database, with its scripted activities
     */
    public static View of(String templateId, JsonNode snapshot, JsonNode employee,
                          List<BaselineEvidence.LearnedRequest> requests, ObjectMapper json) throws IOException {
        JsonNode baseline = snapshot.path("userBaseline");
        if (baseline.isTextual()) {
            baseline = json.readTree(baseline.asText());
        }
        int allowed = (int) requests.stream().filter(request -> "ALLOW".equals(request.finalAction())).count();
        return new View(employee.path("employeeKey").asText(), employee.path("displayName").asText(),
                employee.path("department").asText(), templateId, learned(baseline), taught(employee),
                List.copyOf(requests), requests.size(), allowed, null,
                snapshot.hasNonNull("capturedAt") ? snapshot.path("capturedAt").asText() : null);
    }

    static Learned learned(JsonNode baseline) {
        Integer[] hours = new Integer[24];
        Arrays.fill(hours, 0);
        Integer[] weekdays = new Integer[7];
        Arrays.fill(weekdays, 0);
        for (Map.Entry<String, JsonNode> field : baseline.path("elementFrequencies").properties()) {
            String key = field.getKey();
            int count = field.getValue().asInt();
            if (key.startsWith("hour:")) {
                int hour = Integer.parseInt(key.substring(5));
                if (hour >= 0 && hour < 24) {
                    hours[hour] += count;
                }
            } else if (key.startsWith("day:")) {
                int day = Integer.parseInt(key.substring(4));
                if (day >= 1 && day <= 7) {
                    weekdays[day - 1] += count;
                }
            }
        }
        List<String> devices = new ArrayList<>();
        baseline.path("normalOperatingSystems").forEach(os -> devices.add(os.asText()));
        baseline.path("normalBrowsers").forEach(browser -> devices.add(browser.asText()));
        List<String> networks = new ArrayList<>();
        baseline.path("normalIpBands").forEach(band -> networks.add(band.asText()));
        return new Learned(baseline.path("updateCount").asInt(), List.of(hours), List.of(weekdays),
                List.copyOf(networks), List.copyOf(devices));
    }

    static Taught taught(JsonNode employee) {
        int reads = 0;
        int downloads = 0;
        int exports = 0;
        Integer min = null;
        Integer max = null;
        Map<String, Integer> projects = new TreeMap<>();
        Instant from = null;
        Instant to = null;
        for (JsonNode activity : employee.path("scriptedActivities")) {
            String operation = activity.path("operation").asText();
            String target = activity.path("targetKey").asText();
            switch (operation) {
                case "DOCUMENT_READ" -> reads++;
                case "DOCUMENT_DOWNLOAD" -> downloads++;
                case "EXPORT" -> {
                    exports++;
                    int items = activity.path("items").asInt();
                    min = min == null ? items : Math.min(min, items);
                    max = max == null ? items : Math.max(max, items);
                }
                default -> {
                }
            }
            projects.merge("EXPORT".equals(operation) ? target : projectOf(target), 1, Integer::sum);
            Instant at = Instant.parse(activity.path("observedAt").asText());
            from = from == null || at.isBefore(from) ? at : from;
            to = to == null || at.isAfter(to) ? at : to;
        }
        return new Taught(reads, downloads, exports, min, max, Map.copyOf(projects), from, to);
    }

    /** A document key is {@code PROJECT-TYPE-NUMBER}, where the project key may itself contain a hyphen. */
    static String projectOf(String documentKey) {
        String[] parts = documentKey.split("-");
        if (parts.length < 3) {
            return documentKey;
        }
        return String.join("-", Arrays.copyOf(parts, parts.length - 2));
    }
}
