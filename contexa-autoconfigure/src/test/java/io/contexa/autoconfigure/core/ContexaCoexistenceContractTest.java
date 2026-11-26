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

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.type.MethodMetadata;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
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
            "IamI18nAutoConfiguration#localeResolver",                  // Spring MVC's name; the language of the application (CONTEXA_OWNED only)
            "IamI18nAutoConfiguration#messageSource",                   // the application context's name for its messages
            "CommonRedisAutoConfiguration#stringRedisTemplate",
            "WebSocketConfig#clientInboundChannelExecutor",             // overrides of the message broker's own beans
            "WebSocketConfig#clientOutboundChannelExecutor",
            "WebSocketConfig#brokerChannelExecutor",
            "WebSocketConfig#messageBrokerTaskScheduler",
            "WebSocketConfig#messageBrokerSockJsTaskScheduler",       // the alias Spring gives the same scheduler
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
            Map.entry("PasswordEncoder", "contexa"),
            Map.entry("RoleHierarchy", "contexa"),
            Map.entry("RoleHierarchyImpl", "contexa"),
            Map.entry("OneTimeTokenService", "contexa"),
            Map.entry("JwtDecoder", "contexa"),
            Map.entry("ChatModel", "contexa"),
            Map.entry("EmbeddingModel", "contexa"),
            Map.entry("ChatClient.Builder", "contexa"),
            Map.entry("VectorStore", "contexa"),
            Map.entry("DataSource", "contexa"),
            Map.entry("JdbcTemplate", "contexa"),
            Map.entry("JdbcOperations", "contexa"),
            Map.entry("NamedParameterJdbcTemplate", "contexa"),
            Map.entry("JdbcClient", "contexa"),
            Map.entry("EntityManager", "contexa"),
            Map.entry("EntityManagerFactory", "contexa"),
            Map.entry("PlatformTransactionManager", "contexa"),
            Map.entry("TransactionTemplate", "contexa"),
            Map.entry("RedisTemplate", "contexa"),
            Map.entry("RedissonClient", "contexaRedissonClient"),
            Map.entry("KafkaTemplate", "contexa"),
            Map.entry("ConcurrentKafkaListenerContainerFactory", "contexa"),
            Map.entry("OpenTelemetry", "contexa"),
            Map.entry("Tracer", "contexa"));

    /** The names of the message broker's own executors and scheduler: Contexa's broker overrides them and Spring names them. */
    private static final Set<String> BROKER_NAMES = Set.of("clientInboundChannelExecutor", "clientOutboundChannelExecutor",
            "brokerChannelExecutor", "messageBrokerTaskScheduler");

    /** Beans of the enterprise libraries that these libraries ask for by name and optionally (required = false); the enterprise guard checks they exist. */
    private static final Set<String> DEFINED_BY_THE_OTHER_REPOSITORY = Set.of("contexaPipelineSoarToolExecutionStep");

    private static final Pattern QUALIFIER_NAME = Pattern.compile("@Qualifier\\(\\s*\"(contexa[A-Za-z0-9_]*)\"\\s*\\)");
    private static final Pattern GET_BEAN_NAME = Pattern.compile("\\b(?:getBean|containsBean|getBeanProvider)\\(\\s*\"(contexa[A-Za-z0-9_]*)\"");
    private static final Pattern RESOURCE_NAME = Pattern.compile("@Resource\\(\\s*name\\s*=\\s*\"(contexa[A-Za-z0-9_]*)\"");
    private static final Pattern STEREOTYPE_NAME = Pattern.compile(
            "@(?:Component|Service|Repository|Controller|RestController|Configuration)\\(\\s*(?:value\\s*=\\s*)?\"(contexa[A-Za-z0-9_]*)\"");

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

    /**
     * Spring Security and Spring Boot look these types up for the application with {@code getBeanProvider(T).getIfUnique()} or
     * {@code getBean(T.class)}, which return a bean that is the only one of the type even when it is not an autowire candidate: a bean of
     * Contexa's of such a type is the application's (a login with Contexa's mail, an authorization by Contexa's roles). Contexa's own
     * instance is held in a bean of no shared type, and its code takes it by name.
     */
    private static final Set<String> TYPES_THE_FRAMEWORKS_LOOK_UP = Set.of("PasswordEncoder", "RoleHierarchy", "RoleHierarchyImpl",
            "OneTimeTokenService", "EmailOneTimeTokenService", "JdbcOneTimeTokenService", "InMemoryOneTimeTokenService");

    @Test
    void noBeanOfContexaIsOfATypeTheFrameworksLookUpForTheApplication() throws IOException {
        List<String> violations = new ArrayList<>();
        for (SourceFile file : sources()) {
            for (BeanMethod bean : beanMethods(file.source())) {
                String type = bean.returnType().replaceAll("<.*", "");
                if (TYPES_THE_FRAMEWORKS_LOOK_UP.contains(type.substring(type.lastIndexOf('.') + 1)) && !bean.givesWay()) {
                    violations.add(file.path() + " : bean method " + bean.method() + " returns " + bean.returnType());
                }
            }
        }
        assertThat(violations)
                .as("hold it in a HeldBean (or another bean of no shared type): a sole bean of the type is found by the frameworks")
                .isEmpty();
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
    void noStringOperationDependsOnTheApplicationsDefaultLocale() throws IOException {
        List<String> violations = new ArrayList<>();
        Pattern caseChange = Pattern.compile("\\.to(?:Lower|Upper)Case\\(\\s*\\)");
        Pattern format = Pattern.compile("String\\.format\\(\\s*\"(?:[^\"\\\\]|\\\\.)*%[-#+ 0,(]*\\d*(?:\\.\\d+)?[dfeEgGx]");
        for (SourceFile file : sources()) {
            if (caseChange.matcher(file.source()).find()) {
                violations.add(file.path() + " : toLowerCase()/toUpperCase() without Locale.ROOT (in a Turkish JVM \"I\".toLowerCase() is not \"i\")");
            }
            if (format.matcher(file.source()).find()) {
                violations.add(file.path() + " : String.format with a number directive and no Locale (in some default locales the digits are not 0-9)");
            }
        }
        assertThat(violations).as("an application's default locale must not change what Contexa's identifiers, addresses and SQL say").isEmpty();
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
    void everyContexaNameAskedForByStringIsABeanSomewhere() throws IOException {
        Set<String> defined = new TreeSet<>();
        List<SourceFile> sources = sources();
        for (SourceFile file : sources) {
            for (BeanMethod bean : beanMethods(file.source())) {
                defined.addAll(bean.names());
            }
            Matcher named = STEREOTYPE_NAME.matcher(file.source());
            while (named.find()) {
                defined.add(named.group(1));
            }
        }
        List<String> violations = new ArrayList<>();
        for (SourceFile file : sources) {
            for (String name : referencedByString(file.source())) {
                if (!defined.contains(name) && !DEFINED_BY_THE_OTHER_REPOSITORY.contains(name)) {
                    violations.add(file.path() + " : \"" + name + "\" is asked for by name, and no bean of that name is defined");
                }
            }
        }
        assertThat(violations)
                .as("a name written as a string is not checked by the compiler; one that no bean has fails when the bean is first asked for")
                .isEmpty();
    }

    @Test
    void theNamesAskedForByStringAreFound() {
        String source = """
                class Sample {
                    Sample(@Qualifier("contexaOne") Thing one, @Qualifier(CONSTANT) Thing two) {
                        beanFactory.getBean("contexaTwo", Thing.class);
                        context.containsBean("contexaThree");
                    }
                    @DependsOn({"contexaFour", "otherBean"})
                    @Resource(name = "contexaFive")
                    Thing five;
                    @ConditionalOnBean(name = "contexaNotChecked")
                    Thing six;
                }
                """;

        assertThat(referencedByString(source)).containsExactlyInAnyOrder("contexaOne", "contexaTwo", "contexaThree", "contexaFour", "contexaFive");
    }

    /** The contexa-prefixed bean names a source asks for as a string (a condition on a name may name a bean that is not there). */
    private static Set<String> referencedByString(String source) {
        Set<String> names = new TreeSet<>();
        for (Pattern pattern : List.of(QUALIFIER_NAME, GET_BEAN_NAME, RESOURCE_NAME)) {
            Matcher matcher = pattern.matcher(source);
            while (matcher.find()) {
                names.add(matcher.group(1));
            }
        }
        Matcher depends = Pattern.compile("@DependsOn\\(([^)]*)\\)").matcher(source);
        while (depends.find()) {
            Matcher literal = Pattern.compile("\"(contexa[A-Za-z0-9_]*)\"").matcher(depends.group(1));
            while (literal.find()) {
                names.add(literal.group(1));
            }
        }
        return names;
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
    void theGuardReadsTheReturnTypeOfABeanMethod() {
        String source = """
                class Config {
                    @Bean(name = "contexaPasswordEncoder")
                    public PasswordEncoder passwordEncoder() {
                        return null;
                    }

                    @Bean(name = "contexaRoleHierarchy")
                    public HeldBean<RoleHierarchyImpl> roleHierarchy() {
                        return null;
                    }

                    @Bean(name = "contexaOneTimeTokenService")
                    @ConditionalOnMissingBean
                    public io.example.OneTimeTokenService oneTimeToken() {
                        return null;
                    }
                }
                """;

        List<BeanMethod> beans = beanMethods(source);

        assertThat(beans).extracting(BeanMethod::returnType)
                .containsExactly("PasswordEncoder", "HeldBean<RoleHierarchyImpl>", "io.example.OneTimeTokenService");
        assertThat(beans).extracting(bean -> bean.returnType().replaceAll("<.*", ""))
                .filteredOn(type -> TYPES_THE_FRAMEWORKS_LOOK_UP.contains(type.substring(type.lastIndexOf('.') + 1)))
                .containsExactly("PasswordEncoder", "io.example.OneTimeTokenService");
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

    // ------------------------------------------------------------------ M0 of the operating-mode plan: the security types

    /**
     * M0 of the operating-mode plan (docs/agent/운영모드-정상화-구현계획.md, R-6 and R-9): the list of the types the frameworks
     * look up by type for the application ({@link #TYPES_THE_FRAMEWORKS_LOOK_UP}), widened to the security types an
     * application has of its own. Spring Security and Spring Boot take one of these for the application's own sign-in and
     * authorization when it is the only one of its type, and take none when there are several (a global authentication
     * manager left without a provider); a bean of Contexa's that is visible by type is in that count. The check reads the
     * compiled bean methods, so that a subtype counts (Contexa's store, provider and evaluators implement these types). It
     * is a static check of the definitions; what an application gets while it runs is HostComponentCoexistencePostgresTest.
     */
    private static final List<String> SECURITY_TYPES_THE_FRAMEWORKS_LOOK_UP = List.of(
            "org.springframework.security.core.userdetails.UserDetailsService",
            "org.springframework.security.authentication.AuthenticationProvider",
            "org.springframework.security.authentication.AuthenticationManager",
            "org.springframework.security.web.context.SecurityContextRepository",
            "org.springframework.security.access.PermissionEvaluator",
            "org.springframework.security.oauth2.client.registration.ClientRegistrationRepository",
            "org.springframework.security.oauth2.jwt.JwtDecoder",
            "net.javacrumbs.shedlock.core.LockProvider",
            "com.querydsl.jpa.impl.JPAQueryFactory");

    /**
     * The watched types no framework counts or picks for the application: only the application's own code asks for them by
     * type, and such an injection passes over a bean that is no default candidate. A bean of Contexa's of one of these types
     * that is no default candidate is out of the application's way (F-02 of docs/agent/운영모드-정상화-구현계획.md). The types
     * Spring Security counts with the beans that are no default candidates (F-8) are not among them.
     */
    private static final Set<String> TYPES_ONLY_THE_APPLICATIONS_CODE_INJECTS = Set.of("com.querydsl.jpa.impl.JPAQueryFactory");

    /**
     * The same security types at Contexa's own injection points (R-6): asked for by type, Contexa's code is given the
     * application's bean when the application has one, or fails when there are several. The types already listed in
     * {@link #SHARED_TYPES} (the decoder, the entity manager, the Redis template) are checked there.
     */
    private static final List<String> SECURITY_TYPES_ASKED_FOR_BY_NAME = List.of("UserDetailsService", "AuthenticationProvider",
            "AuthenticationManager", "SecurityContextRepository", "PermissionEvaluator", "ClientRegistrationRepository",
            "JPAQueryFactory", "LockProvider");

    /** The key Spring Security reads to apply a configurer to every {@code HttpSecurity}, the application's chains included. */
    private static final String EVERY_HTTP_SECURITY = "org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer=";

    @Test
    @DisplayName("보안 구성요소 타입의 Contexa 빈은 호스트가 타입으로 찾을 때 보이지 않는다(정적 검사: 컴파일된 빈 정의)")
    void noBeanOfContexaIsOfASecurityTypeTheFrameworksLookUpForTheApplication() throws IOException {
        ClassLoader loader = getClass().getClassLoader();
        List<Class<?>> watched = new ArrayList<>();
        for (String name : SECURITY_TYPES_THE_FRAMEWORKS_LOOK_UP) {
            watched.add(GuardTypes.load(name, loader));
        }
        SimpleMetadataReaderFactory readers = new SimpleMetadataReaderFactory(loader);
        List<String> violations = new ArrayList<>();
        List<String> unread = new ArrayList<>();
        for (SourceFile file : sources()) {
            String className = compiledName(file);
            if (className == null) {
                continue;
            }
            Deque<String> classes = new ArrayDeque<>(List.of(className));
            while (!classes.isEmpty()) {
                String current = classes.pop();
                MetadataReader reader;
                try {
                    reader = readers.getMetadataReader(current);
                } catch (IOException notCompiled) {
                    unread.add(current);
                    continue;
                }
                classes.addAll(List.of(reader.getClassMetadata().getMemberClassNames()));
                for (MethodMetadata method : reader.getAnnotationMetadata().getAnnotatedMethods(Bean.class.getName())) {
                    Class<?> returned;
                    try {
                        returned = Class.forName(method.getReturnTypeName(), false, loader);
                    } catch (ClassNotFoundException | LinkageError notLoadable) {
                        // a library type of the distributed mode (Redisson, Spring Statemachine's Redis repositories) is on the
                        // class path of the distributed tests only; it is said here and not checked. A type of Contexa's is
                        // always loadable, so one that is not is a failure of this check.
                        if (method.getReturnTypeName().startsWith("io.contexa.")) {
                            unread.add(current + "#" + method.getMethodName() + " returns " + method.getReturnTypeName());
                        } else {
                            System.out.println("NOT CHECKED (not on this class path): " + current + "#" + method.getMethodName()
                                    + " returns " + method.getReturnTypeName());
                        }
                        continue;
                    }
                    for (Class<?> lookedUp : watched) {
                        if (lookedUp.isAssignableFrom(returned) && !givesWayTo(method, returned, lookedUp, loader)
                                && !keptOutOfTheApplicationsInjection(method, lookedUp)) {
                            violations.add(file.path() + " : bean method " + method.getMethodName() + " returns "
                                    + returned.getSimpleName() + ", seen by the application's lookups of " + lookedUp.getSimpleName());
                        }
                    }
                }
            }
        }
        SoftAssertions.assertSoftly(softly -> {
            softly.assertThat(violations)
                    .as("hold it in a HeldBean (or another bean of no shared type), as the PasswordEncoder is: a bean of the type is"
                            + " counted, and taken, by the frameworks when the application asks for its own")
                    .isEmpty();
            softly.assertThat(unread).as("bean methods this check could not read").isEmpty();
        });
    }

    @Test
    @DisplayName("Contexa 코드는 보안 구성요소 타입을 Contexa 이름으로만 주입받는다(정적 검사: 소스의 주입 지점)")
    void contexaAsksForTheSecurityTypesByItsOwnName() throws IOException {
        List<String> violations = new ArrayList<>();
        for (SourceFile file : sources()) {
            String source = file.source();
            for (BeanMethod bean : beanMethods(source)) {
                checkSecurityTypes(file, "bean method " + bean.method(), bean.parameters(), violations);
            }
            if (STEREOTYPE.matcher(source).find()) {
                for (String parameters : constructorParameters(file.name(), source)) {
                    checkSecurityTypes(file, "constructor", parameters, violations);
                }
                for (String field : autowiredFields(source)) {
                    checkSecurityTypes(file, "autowired field", field, violations);
                }
                if (source.contains("@RequiredArgsConstructor") || source.contains("@AllArgsConstructor")) {
                    for (String type : finalFieldTypes(source)) {
                        if (securityTypeOf(type) != null) {
                            violations.add(file.path() + " : a generated (Lombok) constructor takes " + type
                                    + ", which cannot carry the qualifier; write the constructor");
                        }
                    }
                }
            }
        }
        assertThat(violations)
                .as("an injection point of a security type without Contexa's name gets the application's bean of the type when it has one")
                .isEmpty();
    }

    @Test
    @DisplayName("라이브러리는 앱 전체에 ShedLock 잠금을 켜지 않는다(정적 검사: 소스)")
    void noLibraryTurnsOnSchedulerLocksForTheWholeApplication() throws IOException {
        List<String> violations = new ArrayList<>();
        Pattern global = Pattern.compile("(?m)^\\s*@EnableSchedulerLock\\b");
        for (SourceFile file : sources()) {
            if (global.matcher(file.source()).find() && !file.source().contains("@SpringBootApplication")) {
                violations.add(file.path() + " : @EnableSchedulerLock locks every @SchedulerLock method of the application, with the"
                        + " lock provider the application's lookups find");
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("라이브러리는 호스트 체인까지 모든 HttpSecurity에 붙는 구성기를 등록하지 않는다(정적 검사: spring.factories)")
    void noLibraryRegistersAConfigurerForEveryHttpSecurity() throws IOException {
        Path root = repositoryRoot();
        List<String> violations = new ArrayList<>();
        for (String library : LIBRARIES) {
            Path factories = root.resolve(library).resolve("src").resolve("main").resolve("resources")
                    .resolve("META-INF").resolve("spring.factories");
            if (Files.exists(factories) && Files.readString(factories, StandardCharsets.UTF_8).contains(EVERY_HTTP_SECURITY)) {
                violations.add(root.relativize(factories).toString().replace('\\', '/') + " : a configurer under "
                        + EVERY_HTTP_SECURITY.replace("=", "") + " is applied to the application's own chains as well");
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("보안 구성요소 검사가 하위 타입과 양보 조건을 그대로 읽는다")
    void theSecurityTypeGuardReadsSubtypesAndGivingWay() throws IOException {
        ClassLoader loader = getClass().getClassLoader();
        SimpleMetadataReaderFactory readers = new SimpleMetadataReaderFactory(loader);
        MetadataReader reader = readers.getMetadataReader(GuardSample.class.getName());
        Class<?> store = GuardTypes.load("org.springframework.security.core.userdetails.UserDetailsService", loader);
        Map<String, Boolean> givesWay = new TreeMap<>();
        for (MethodMetadata method : reader.getAnnotationMetadata().getAnnotatedMethods(Bean.class.getName())) {
            Class<?> returned = GuardTypes.load(method.getReturnTypeName(), loader);
            givesWay.put(method.getMethodName(), store.isAssignableFrom(returned) && givesWayTo(method, returned, store, loader));
        }

        assertThat(givesWay).containsExactlyInAnyOrderEntriesOf(Map.of(
                "byTheType", true, "byASubtype", false, "byName", false, "noCondition", false));
        assertThat(securityTypeOf("ObjectProvider<UserDetailsService>")).isEqualTo("UserDetailsService");
        assertThat(securityTypeOf("UnifiedUserDetailsService")).as("a type of Contexa's own is no shared type").isNull();
    }

    /** What the guard reads: four bean methods of a store, one of which gives way to the application's store. */
    static class GuardSample {

        @Bean
        @ConditionalOnMissingBean(type = "org.springframework.security.core.userdetails.UserDetailsService")
        SampleStore byTheType() {
            return null;
        }

        @Bean
        @ConditionalOnMissingBean
        SampleStore byASubtype() {
            return null;
        }

        @Bean
        @ConditionalOnMissingBean(name = "contexaSampleStore")
        SampleStore byName() {
            return null;
        }

        @Bean
        SampleStore noCondition() {
            return null;
        }
    }

    /** A store of the sample's own, as Contexa's store is a type of its own that implements the shared one. */
    abstract static class SampleStore implements UserDetailsService {
    }

    /**
     * Whether a bean method stands back when the application has a bean of the looked-up type: its
     * {@code @ConditionalOnMissingBean} names that type or a supertype of it, or names nothing and returns such a type. A
     * condition on a name or an annotation does not see the application's bean of the type.
     */
    /** Whether the bean is no default candidate and of a type only the application's own code injects. */
    private static boolean keptOutOfTheApplicationsInjection(MethodMetadata method, Class<?> lookedUp) {
        if (!TYPES_ONLY_THE_APPLICATIONS_CODE_INJECTS.contains(lookedUp.getName())) {
            return false;
        }
        Map<String, Object> bean = method.getAnnotationAttributes(Bean.class.getName());
        return bean != null && Boolean.FALSE.equals(bean.get("defaultCandidate"));
    }

    private static boolean givesWayTo(MethodMetadata method, Class<?> returned, Class<?> lookedUp, ClassLoader loader) {
        Map<String, Object> missing = method.getAnnotationAttributes(ConditionalOnMissingBean.class.getName(), true);
        if (missing == null) {
            return false;
        }
        List<String> types = new ArrayList<>(List.of((String[]) missing.get("value")));
        types.addAll(List.of((String[]) missing.get("type")));
        if (types.isEmpty()) {
            return ((String[]) missing.get("name")).length == 0 && ((String[]) missing.get("annotation")).length == 0
                    && returned.isAssignableFrom(lookedUp);
        }
        for (String type : types) {
            try {
                if (Class.forName(type, false, loader).isAssignableFrom(lookedUp)) {
                    return true;
                }
            } catch (ClassNotFoundException | LinkageError notLoadable) {
                // a condition on a type that is not on the class path does not see the application's bean of the looked-up type
            }
        }
        return false;
    }

    private static void checkSecurityTypes(SourceFile file, String where, String parameters, List<String> violations) {
        for (String parameter : split(parameters)) {
            String stripped = parameter.replaceAll("@\\w+(?:\\([^)]*\\))?", " ").replaceAll("\\bfinal\\b", " ").trim().replaceAll("\\s+", " ");
            int space = stripped.lastIndexOf(' ');
            String type = space < 0 ? stripped : stripped.substring(0, space);
            if (securityTypeOf(type) == null) {
                continue;
            }
            Matcher qualifier = Pattern.compile("@Qualifier\\(\\s*(?:\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))\\s*\\)").matcher(parameter);
            String value = null;
            if (qualifier.find()) {
                value = qualifier.group(1) != null ? qualifier.group(1) : constant(file.source(), qualifier.group(2));
            }
            if (value == null || !value.startsWith("contexa")) {
                violations.add(file.path() + " : " + where + " takes \"" + parameter.trim().replaceAll("\\s+", " ")
                        + "\" without @Qualifier(\"contexa...\")");
            }
        }
    }

    private static String securityTypeOf(String type) {
        for (String security : SECURITY_TYPES_ASKED_FOR_BY_NAME) {
            if (Pattern.compile("(?<![\\w.])" + security + "(?![\\w])").matcher(type).find()) {
                return security;
            }
        }
        return null;
    }

    /** The binary name of the top-level class a source file compiles to, or null for a package or module descriptor. */
    private static String compiledName(SourceFile file) {
        String path = file.path();
        int sources = path.indexOf("src/main/java/");
        if (sources < 0 || path.endsWith("package-info.java") || path.endsWith("module-info.java")) {
            return null;
        }
        return path.substring(sources + "src/main/java/".length(), path.length() - ".java".length()).replace('/', '.');
    }

    /** Loads the types the guard compares against; each of them is on the class path of these tests. */
    private static final class GuardTypes {

        private GuardTypes() {
        }

        static Class<?> load(String name, ClassLoader loader) {
            try {
                return Class.forName(name, false, loader);
            } catch (ClassNotFoundException missing) {
                throw new IllegalStateException(name + " is not on the class path of this test", missing);
            }
        }
    }

    // ------------------------------------------------------------------ reading the sources

    record SourceFile(String path, String name, String source) {
    }

    record BeanMethod(String method, List<String> names, boolean givesWay, boolean overrides, String parameters, String returnType) {
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
            String returnType = head.contains(" ") ? head.substring(0, head.lastIndexOf(' ')).trim() : "";
            returnType = returnType.substring(returnType.lastIndexOf(' ') + 1);
            result.add(new BeanMethod(method, namesOf(attributes, source, method),
                    annotations.contains("@ConditionalOnMissingBean"), annotations.contains("@Override"), parameters, returnType));
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
