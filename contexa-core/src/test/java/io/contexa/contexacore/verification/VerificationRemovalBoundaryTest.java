package io.contexa.contexacore.verification;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R4 (redesign appendix A, section 8 item 2): the core files the plan removes are listed by plan item in
 * {@code prompt-inspection/r4-removed-core.txt}. Until they are deleted, no core source outside the list may refer to a
 * listed class, so deleting the listed files never breaks what stays.
 */
class VerificationRemovalBoundaryTest {

    private static final Path MAIN = Path.of("src/main/java/io/contexa/contexacore");

    @ParameterizedTest
    @ValueSource(strings = {"R4-C1", "R4-C1b", "R4-C1c", "R4-C2", "R4-C3", "R4-C4", "R4-C5", "R4-C6", "R4-C7", "R4-C8",
            "R4-C9", "R4-C10", "R4-C11"})
    void noKeptCoreSourceRefersToAClassThePlanItemRemoves(String item) throws IOException {
        Map<String, List<String>> removedByItem = removedByItem();
        Set<String> removedPaths = removedByItem.values().stream().flatMap(List::stream).collect(Collectors.toSet());
        List<String> names = removedByItem.getOrDefault(item, List.of()).stream()
                .map(path -> path.substring(path.lastIndexOf('/') + 1, path.length() - ".java".length()))
                .toList();
        assertThat(names).as("files listed for %s", item).isNotEmpty();
        Pattern referenced = Pattern.compile("\\b(" + String.join("|", names) + ")\\b");

        List<String> references = new ArrayList<>();
        try (Stream<Path> sources = Files.walk(MAIN)) {
            for (Path source : sources.filter(path -> path.toString().endsWith(".java")).toList()) {
                String relative = MAIN.relativize(source).toString().replace('\\', '/');
                if (removedPaths.contains(relative)) {
                    continue;
                }
                var matcher = referenced.matcher(Files.readString(source, StandardCharsets.UTF_8));
                while (matcher.find()) {
                    references.add(relative + " -> " + matcher.group(1));
                }
            }
        }
        assertThat(references.stream().distinct().toList()).as("kept sources referring to %s classes", item).isEmpty();
    }

    private static Map<String, List<String>> removedByItem() throws IOException {
        try (InputStream in = VerificationRemovalBoundaryTest.class.getResourceAsStream(
                "/prompt-inspection/r4-removed-core.txt")) {
            assertThat(in).isNotNull();
            return Arrays.stream(new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n"))
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .map(line -> line.split(" ", 2))
                    .collect(Collectors.groupingBy(parts -> parts[0],
                            Collectors.mapping(parts -> parts[1], Collectors.toList())));
        }
    }
}
