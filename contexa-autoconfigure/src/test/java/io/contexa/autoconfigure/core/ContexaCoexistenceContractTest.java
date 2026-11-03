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
package io.contexa.autoconfigure.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contexa lives in applications it knows nothing about, so what it puts into the application's context must not meet what the application
 * has put there. These rules keep that so, read from the sources of the libraries that load into an application:
 * <ol>
 *   <li>every bean has a name that starts with {@code contexa}, except the names of the framework (listed here, with the reason);</li>
 *   <li>a framework name is used only where Contexa gives way (the bean exists when the application has none of the type) or overrides
 *       a bean method of Spring itself;</li>
 *   <li>a bean of a shared generic type (the JSON mapper, the model mapper, the executors and schedulers) is asked for by the name of
 *       Contexa's own bean wherever Spring resolves a constructor, a bean method or an autowired field;</li>
 *   <li>an asynchronous method names Contexa's executor, a cached method names Contexa's cache manager, and no library enables
 *       scheduling, asynchronous execution, caching, Kafka listeners, retrying or JPA auditing for the whole application.</li>
 * </ol>
 */
class ContexaCoexistenceContractTest {

    /** The libraries that load into an application (the MCP servers are applications of their own). */
    private static final List<String> LIBRARIES = List.of("contexa-common", "contexa-core", "contexa-iam", "contexa-identity", "contexa-autoconfigure");

    /**
     * Beans whose name is the framework's own, with the reason. The key is the file and the bean. A new name here needs the same reason:
     * Contexa provides the bean only when the application has none of the type, or it overrides Spring's own bean method.
     */
    private static final Set<String> FRAMEWORK_NAMES = Set.of(
            "ContexaOwnedDataSourceAutoConfiguration#dataSource",       // the application's data source, when Contexa owns the application
            "CoreDataAutoConfiguration#jdbcTemplate",                   // the same
            "CoreDataAutoConfiguration#transactionTemplate",            // the same
            "IamI18nAutoConfiguration#localeResolver",                  // Spring MVC's name; the language of the application
            "IamI18nAutoConfiguration#messageSource",                   // the application context's name for its messages
            "IamInfrastructureAutoConfiguration#passwordEncoder",       // Spring Security's default encoder, as it would use without a bean
            "IdentityOAuth2AutoConfiguration#authorizationServerSettings",
            "IdentityOAuth2AutoConfiguration#jwkSource",
            "IdentityOAuth2AutoConfiguration#jwtDecoder",
            "IdentityOAuth2AutoConfiguration#registeredClientRepository",
            "IdentitySecurityCoreAutoConfiguration#securityFilterChain", // the application's chain, when Contexa owns sign-in
            "CommonRedisAutoConfiguration#stringRedisTemplate",
            "WebSocketConfig#clientInboundChannelExecutor",             // overrides of the message broker's own beans
            "WebSocketConfig#clientOutboundChannelExecutor",
            "WebSocketConfig#brokerChannelExecutor",
            "WebSocketConfig#messageBrokerTaskScheduler",
            "WebSocketConfig#stompWebSocketHandlerMapping");

    /** The shared generic types and the qualifier prefix a Contexa injection point must name. */
    private static final Map<String, String> SHARED_TYPES = Map.ofEntries(
            Map.entry("ObjectMapper", "contexaObjectMapper"),
            Map.entry("ModelMapper", "contexaModelMapper"),
            Map.entry("Executor", "contexa"),
            Map.entry("TaskExecutor", "contexa"),
            Map.entry("ThreadPoolTaskExecutor", "contexa"),
            Map.entry("AsyncTaskExecutor", "contexa"),
            Map.entry("TaskScheduler", "contexa"),
            Map.entry("ThreadPoolTaskScheduler", "contexa"),
            Map.entry("ExecutorService", "contexa"),
            Map.entry("ScheduledExecutorService", "contexa"),
            Map.entry("RedisTemplate", "contexa"),
            Map.entry("KafkaTemplate", "contexa"),
            Map.entry("ConcurrentKafkaListenerContainerFactory", "contexa"),
            Map.entry("OpenTelemetry", "contexa"),
            Map.entry("Tracer", "contexa"));

    /** The names of the message broker's own executors and scheduler: Contexa's broker overrides them and Spring names them. */
    private static final Set<String> BROKER_NAMES = Set.of("clientInboundChannelExecutor", "clientOutboundChannelExecutor",
            "brokerChannelExecutor", "messageBrokerTaskScheduler");

    private static final Pattern STEREOTYPE = Pattern.compile(
            "@(Component|Service|Repository|Controller|RestController|ControllerAdvice|RestControllerAdvice|Aspect|Configuration)\\b");

    @Test
    void everyBeanNameStartsWithContexaOrIsAFrameworkName() throws IOException {
        List<String> violations = new ArrayList<>();
        for (SourceFile file : sources()) {
            for (BeanMethod bean : beanMethods(file.source())) {
                for (String name : bean.names()) {
                    if (!name.startsWith("contexa") && !FRAMEWORK_NAMES.contains(file.name() + "#" + name)) {
                        violations.add(file.path() + " : bean \"" + name + "\" (method " + bean.method() + ")");
                    }
                }
            }
        }
        assertThat(violations)
                .as("a bean without the contexa prefix can meet a bean of the application with the same name, and the application will not start")
                .isEmpty();
    }

    @Test
    void aFrameworkNameIsUsedOnlyWhereContexaGivesWayOrOverrides() throws IOException {
        List<String> violations = new ArrayList<>();
        Set<String> seen = new TreeSet<>();
        for (SourceFile file : sources()) {
            for (BeanMethod bean : beanMethods(file.source())) {
                for (String name : bean.names()) {
                    String key = file.name() + "#" + name;
                    if (FRAMEWORK_NAMES.contains(key)) {
                        seen.add(key);
                        if (!bean.givesWay() && !bean.overrides()) {
                            violations.add(file.path() + " : \"" + name + "\" is a framework name but Contexa does not give way for it");
                        }
                    }
                }
            }
        }
        assertThat(violations).isEmpty();
        assertThat(seen).as("every entry of the list stands for a bean that exists (remove the entries that do not)")
                .containsExactlyInAnyOrderElementsOf(FRAMEWORK_NAMES);
    }

    @Test
    void sharedGenericTypesAreAskedForByContexasOwnName() throws IOException {
        List<String> violations = new ArrayList<>();
        for (SourceFile file : sources()) {
            String source = file.source();
            boolean stereotype = STEREOTYPE.matcher(source).find();
            for (BeanMethod bean : beanMethods(source)) {
                check(file, "bean method " + bean.method(), bean.parameters(), violations);
            }
            if (stereotype) {
                for (String parameters : constructorParameters(file.name(), source)) {
                    check(file, "constructor", parameters, violations);
                }
                for (String field : autowiredFields(source)) {
                    check(file, "autowired field", field, violations);
                }
                if (source.contains("@RequiredArgsConstructor") || source.contains("@AllArgsConstructor")) {
                    for (String type : finalFieldTypes(source)) {
                        if (sharedTypeOf(type) != null) {
                            violations.add(file.path() + " : a generated (Lombok) constructor takes " + type
                                    + ", which cannot carry the qualifier; write the constructor");
                        }
                    }
                }
            }
        }
        assertThat(violations)
                .as("an injection point of a shared type without Contexa's name gets the application's bean of the type when it has one")
                .isEmpty();
    }

    @Test
    void asyncMethodsNameContexasExecutor() throws IOException {
        List<String> violations = new ArrayList<>();
        Pattern bare = Pattern.compile("(?m)^\\s*@Async\\s*(?:$|(?=@|//))");
        for (SourceFile file : sources()) {
            if (bare.matcher(file.source()).find()) {
                violations.add(file.path() + " : @Async without an executor runs on the application's executor when it enabled asynchronous"
                        + " execution; write @Async(\"contexaTaskExecutor\")");
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    void cachedMethodsUseContexasCacheManager() throws IOException {
        List<String> violations = new ArrayList<>();
        Pattern annotated = Pattern.compile("(?m)^\\s*@(Cacheable|CacheEvict|CachePut|Caching)\\b");
        for (SourceFile file : sources()) {
            if (annotated.matcher(file.source()).find() && !file.source().contains("@CacheConfig(cacheManager = \"contexaCacheManager\")")) {
                violations.add(file.path() + " : cache annotations without @CacheConfig(cacheManager = \"contexaCacheManager\") share the "
                        + "application's cache of the same name when the application enabled caching");
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    void noLibraryTurnsOnForTheWholeApplicationWhatTheApplicationMayHaveLeftOff() throws IOException {
        List<String> violations = new ArrayList<>();
        Pattern global = Pattern.compile("(?m)^\\s*@(EnableScheduling|EnableAsync|EnableCaching|EnableKafka|EnableRetry|EnableJpaAuditing)\\b");
        for (SourceFile file : sources()) {
            Matcher matcher = global.matcher(file.source());
            if (matcher.find() && !file.source().contains("@SpringBootApplication")) {
                violations.add(file.path() + " : @" + matcher.group(1) + " reaches every bean of the application, the application's dormant"
                        + " annotations included; Contexa's scoped support (core/scope) does it for Contexa's beans only");
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    void theScannerReadsBeansTheWayTheRulesNeed() {
        String source = """
                class Sample {
                    static final String NAMED = "contexaNamed";

                    @Bean
                    @ConditionalOnMissingBean
                    public PasswordEncoder passwordEncoder() { return null; }

                    @Bean(name = {"dataSource", "contexaDataSource"})
                    DataSource ds(@Qualifier("contexaObjectMapper") ObjectMapper mapper, ObjectProvider<ObjectMapper> other) { return null; }

                    @Bean(NAMED)
                    Thing fromConstant() { return null; }

                    @Bean(defaultCandidate = false)
                    @Override
                    public Executor clientInboundChannelExecutor() { return null; }
                }
                """;

        List<BeanMethod> beans = beanMethods(source);

        assertThat(beans).extracting(BeanMethod::method).containsExactly("passwordEncoder", "ds", "fromConstant", "clientInboundChannelExecutor");
        assertThat(beans.get(0).names()).containsExactly("passwordEncoder");
        assertThat(beans.get(0).givesWay()).isTrue();
        assertThat(beans.get(1).names()).containsExactly("dataSource", "contexaDataSource");
        assertThat(beans.get(1).givesWay()).isFalse();
        assertThat(beans.get(2).names()).containsExactly("contexaNamed");
        assertThat(beans.get(3).names()).as("defaultCandidate is no name").containsExactly("clientInboundChannelExecutor");
        assertThat(beans.get(3).overrides()).isTrue();

        List<String> violations = new ArrayList<>();
        check(new SourceFile("Sample.java", "Sample", source), "bean method ds", beans.get(1).parameters(), violations);
        assertThat(violations).as("the qualified mapper passes, the provider of an unqualified one does not").hasSize(1);
        assertThat(violations.get(0)).contains("ObjectProvider<ObjectMapper> other");
    }

    @Test
    void theGuardCatchesAConstructorThatTakesTheApplicationsMapper() {
        String source = """
                @Service
                class Svc {
                    private final ObjectMapper mapper;

                    Svc(ObjectMapper m, @Qualifier("contexaObjectMapper") ObjectMapper n, ModelMapper mm, Executor e, @Qualifier("contexaTaskExecutor") Executor ok) {
                    }

                    Svc build() {
                        return new Svc(null, null, null, null, null);
                    }
                }
                """;
        List<String> violations = new ArrayList<>();

        for (String parameters : constructorParameters("Svc", source)) {
            check(new SourceFile("Svc.java", "Svc", source), "constructor", parameters, violations);
        }

        assertThat(violations).hasSize(3);
        assertThat(violations).anySatisfy(line -> assertThat(line).contains("ObjectMapper m"));
        assertThat(violations).anySatisfy(line -> assertThat(line).contains("ModelMapper mm"));
        assertThat(violations).anySatisfy(line -> assertThat(line).contains("Executor e"));
    }

    private static void check(SourceFile file, String where, String parameters, List<String> violations) {
        for (String parameter : split(parameters)) {
            String stripped = parameter.replaceAll("@\\w+(?:\\([^)]*\\))?", " ").replaceAll("\\bfinal\\b", " ").trim().replaceAll("\\s+", " ");
            int space = stripped.lastIndexOf(' ');
            String type = space < 0 ? stripped : stripped.substring(0, space);
            String shared = sharedTypeOf(type);
            if (shared == null) {
                continue;
            }
            Matcher qualifier = Pattern.compile("@Qualifier\\(\\s*(?:\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))\\s*\\)").matcher(parameter);
            String required = SHARED_TYPES.get(shared);
            String value = null;
            if (qualifier.find()) {
                value = qualifier.group(1) != null ? qualifier.group(1) : constant(file.source(), qualifier.group(2));
            }
            if (!(value != null && (value.startsWith(required) || BROKER_NAMES.contains(value)))) {
                violations.add(file.path() + " : " + where + " takes \"" + parameter.trim().replaceAll("\\s+", " ") + "\" without @Qualifier(\"" + required + "...\")");
            }
        }
    }

    private static String constant(String source, String name) {
        Matcher matcher = Pattern.compile("String\\s+" + Pattern.quote(name) + "\\s*=\\s*\"([^\"]+)\"").matcher(source);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String sharedTypeOf(String type) {
        for (String shared : SHARED_TYPES.keySet()) {
            if (Pattern.compile("(?<![\\w.])" + shared + "(?![\\w])").matcher(type).find()) {
                return shared;
            }
        }
        return null;
    }

    /** Parameters of a top-level comma list, generics and annotations kept whole. */
    private static List<String> split(String parameters) {
        List<String> result = new ArrayList<>();
        int depth = 0;
        boolean inString = false;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < parameters.length(); i++) {
            char c = parameters.charAt(i);
            if (inString) {
                current.append(c);
                if (c == '\\') {
                    current.append(parameters.charAt(++i));
                }
                else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            }
            else if (c == '<' || c == '(' || c == '{') {
                depth++;
            }
            else if (c == '>' || c == ')' || c == '}') {
                depth--;
            }
            else if (c == ',' && depth == 0) {
                result.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(c);
        }
        if (!current.toString().isBlank()) {
            result.add(current.toString());
        }
        return result;
    }

    private static List<String> constructorParameters(String className, String source) {
        List<String> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("(?<![\\w.])(?<!new )" + Pattern.quote(className) + "\\s*\\(").matcher(source);
        while (matcher.find()) {
            int open = matcher.end() - 1;
            int close = closing(source, open);
            String after = source.substring(close).stripLeading();
            if (after.startsWith("{") || after.startsWith("throws")) {
                result.add(source.substring(open + 1, close - 1));
            }
        }
        return result;
    }

    private static List<String> autowiredFields(String source) {
        List<String> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("@Autowired(?:\\([^)]*\\))?\\s+((?:@\\w+(?:\\([^)]*\\))?\\s+)*(?:private\\s+|protected\\s+|public\\s+)?(?:final\\s+)?[\\w.]+(?:<[^;>]*>)?\\s+\\w+)\\s*[;=]")
                .matcher(source);
        while (matcher.find()) {
            result.add(matcher.group(1));
        }
        return result;
    }

    private static List<String> finalFieldTypes(String source) {
        List<String> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("(?m)^\\s*(?:private\\s+|protected\\s+|public\\s+)?final\\s+([\\w.]+(?:<[^;>]*>)?)\\s+\\w+\\s*;").matcher(source);
        while (matcher.find()) {
            result.add(matcher.group(1));
        }
        return result;
    }

    // ------------------------------------------------------------------ reading the sources

    record SourceFile(String path, String name, String source) {
    }

    record BeanMethod(String method, List<String> names, boolean givesWay, boolean overrides, String parameters) {
    }

    private static List<SourceFile> sources() throws IOException {
        Path root = repositoryRoot();
        List<SourceFile> result = new ArrayList<>();
        for (String library : LIBRARIES) {
            Path main = root.resolve(library).resolve("src").resolve("main");
            if (!Files.isDirectory(main)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(main)) {
                for (Path file : files.filter(path -> path.toString().endsWith(".java")).toList()) {
                    String name = file.getFileName().toString().replace(".java", "");
                    String source = Files.readString(file, StandardCharsets.UTF_8).replace("\r\n", "\n");
                    result.add(new SourceFile(root.relativize(file).toString().replace('\\', '/'), name, source));
                }
            }
        }
        assertThat(result).as("the sources of the libraries were found").isNotEmpty();
        return result;
    }

    private static List<BeanMethod> beanMethods(String source) {
        List<BeanMethod> result = new ArrayList<>();
        Matcher bean = Pattern.compile("@Bean\\b").matcher(source);
        while (bean.find()) {
            int index = skipWhitespace(source, bean.end());
            String attributes = "";
            if (index < source.length() && source.charAt(index) == '(') {
                int end = closing(source, index);
                attributes = source.substring(index, end);
                index = end;
            }
            StringBuilder following = new StringBuilder();
            int cursor = index;
            while (true) {
                cursor = skipWhitespace(source, cursor);
                if (cursor < source.length() && source.charAt(cursor) == '@') {
                    int start = cursor++;
                    while (cursor < source.length() && (Character.isJavaIdentifierPart(source.charAt(cursor)) || source.charAt(cursor) == '.')) {
                        cursor++;
                    }
                    int probe = skipWhitespace(source, cursor);
                    if (probe < source.length() && source.charAt(probe) == '(') {
                        cursor = closing(source, probe);
                    }
                    following.append(source, start, cursor).append('\n');
                    continue;
                }
                break;
            }
            int open = source.indexOf('(', cursor);
            String head = source.substring(cursor, open).trim();
            String method = head.substring(head.lastIndexOf(' ') + 1);
            int close = closing(source, open);
            String parameters = source.substring(open + 1, close - 1);
            String annotations = precedingAnnotations(source, bean.start()) + attributes + following;
            result.add(new BeanMethod(method, namesOf(attributes, source, method),
                    annotations.contains("@ConditionalOnMissingBean"), annotations.contains("@Override"), parameters));
        }
        return result;
    }

    private static List<String> namesOf(String attributes, String source, String method) {
        String list = null;
        Matcher named = Pattern.compile("\\b(?:name|value)\\s*=\\s*(\\{[^}]*\\}|[^,)]+)").matcher(attributes);
        if (named.find()) {
            list = named.group(1);
        }
        else {
            Matcher positional = Pattern.compile("^\\(\\s*(\\{[^}]*\\}|\"[^\"]*\"|[A-Z_][A-Z0-9_]*)\\s*[,)]").matcher(attributes);
            if (positional.find()) {
                list = positional.group(1);
            }
        }
        if (list == null) {
            return List.of(method);
        }
        List<String> names = new ArrayList<>();
        for (String token : list.replace("{", "").replace("}", "").split(",")) {
            String value = token.trim();
            if (value.startsWith("\"")) {
                names.add(value.replace("\"", ""));
            }
            else if (!value.isEmpty()) {
                Matcher constant = Pattern.compile("String\\s+" + Pattern.quote(value) + "\\s*=\\s*\"([^\"]+)\"").matcher(source);
                names.add(constant.find() ? constant.group(1) : "<unresolved " + value + ">");
            }
        }
        return names;
    }

    /** The annotation lines directly above a {@code @Bean}: up to a blank line, a comment or the end of the previous member. */
    private static String precedingAnnotations(String source, int at) {
        StringBuilder block = new StringBuilder();
        int lineStart = source.lastIndexOf('\n', at - 1) + 1;
        while (lineStart > 0) {
            int previousStart = source.lastIndexOf('\n', lineStart - 2) + 1;
            String line = source.substring(previousStart, lineStart - 1).trim();
            if (line.isEmpty() || line.endsWith(";") || line.endsWith("{") || line.endsWith("}")
                    || line.startsWith("//") || line.startsWith("/*") || line.startsWith("*")) {
                break;
            }
            block.insert(0, line + "\n");
            lineStart = previousStart;
        }
        return block + source.substring(source.lastIndexOf('\n', at - 1) + 1, at);
    }

    private static int skipWhitespace(String source, int index) {
        while (index < source.length() && Character.isWhitespace(source.charAt(index))) {
            index++;
        }
        return index;
    }

    /** The index after the parenthesis that closes the one at {@code open}; strings and characters are skipped. */
    private static int closing(String source, int open) {
        int depth = 0;
        for (int i = open; i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '"') {
                i++;
                while (i < source.length() && source.charAt(i) != '"') {
                    if (source.charAt(i) == '\\') {
                        i++;
                    }
                    i++;
                }
            }
            else if (c == '\'') {
                i++;
                while (i < source.length() && source.charAt(i) != '\'') {
                    if (source.charAt(i) == '\\') {
                        i++;
                    }
                    i++;
                }
            }
            else if (c == '(') {
                depth++;
            }
            else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return i + 1;
                }
            }
        }
        throw new IllegalStateException("no closing parenthesis for the one at " + open);
    }

    private static Path repositoryRoot() {
        Path current = Path.of("").toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isDirectory(current.resolve("contexa-core")) && Files.isDirectory(current.resolve("contexa-autoconfigure"))) {
                return current;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("the repository root (with contexa-core and contexa-autoconfigure) was not found above "
                + Path.of("").toAbsolutePath());
    }
}
