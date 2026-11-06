/* Copyright 2026 The Contexa Project */
package io.contexa.autoconfigure.ai;

import io.contexa.autoconfigure.core.infra.ContexaPlatformActivation;
import io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurationImportSelector;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.AnnotatedBeanDefinitionReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ConfigurationClassPostProcessor;
import org.springframework.context.annotation.DeferredImportSelector;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.type.AnnotationMetadata;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * PR-39: where {@code @EnableAISecurity} stands may not decide whether an application starts. The real configuration
 * classes are parsed the way a context parses them; only the beans are not created, so what Contexa's beans need does not
 * matter here. Moving the annotation is the only thing the grid changes, as in the measurement that proved the cause.
 */
class EnableAiSecurityPlacementTest {

    private static final String CONTEXA_PLATFORM = "contexaPlatformDslConfig";
    private static final String APPLICATION_PLATFORM = "applicationPlatform";

    @BeforeEach
    void forgetTheLastSelection() {
        AutoConfigurationStandIn.activeWhenSelected = null;
        LaterAutoConfigurationStandIn.activeWhenSelected = null;
    }

    static Stream<Arguments> placements() {
        return Stream.of(
                Arguments.of("switch parsed before the declaration", new Class<?>[]{Switch.class, Declaration.class}),
                Arguments.of("switch parsed after the declaration", new Class<?>[]{Declaration.class, Switch.class}),
                Arguments.of("switch and declaration in one class", new Class<?>[]{SwitchWithDeclaration.class}),
                Arguments.of("declaration imported by the switch's class", new Class<?>[]{SwitchImportingDeclaration.class}),
                Arguments.of("declaration inside the switch's class", new Class<?>[]{SwitchWithNestedDeclaration.class}));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("placements")
    void theApplicationsPlatformConfigIsTheOnlyOneWhereverTheSwitchStands(String placement, Class<?>[] application) {
        DefaultListableBeanFactory beans = parse(new StandardEnvironment(), application);

        assertThat(beans.getBeanNamesForType(PlatformConfig.class)).containsExactly(APPLICATION_PLATFORM);
    }

    @Test
    void anApplicationWithoutAPlatformConfigGetsContexasDefaultOne() {
        DefaultListableBeanFactory beans = parse(new StandardEnvironment(), Switch.class);

        assertThat(beans.getBeanNamesForType(PlatformConfig.class)).containsExactly(CONTEXA_PLATFORM);
    }

    /** The application's own beans keep the order they have without Contexa, wherever the switch stands. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("orders")
    void theApplicationsBeansKeepTheirOrder(String placement, Class<?>[] application) {
        List<String> withoutContexa = applicationBeans(parse(new StandardEnvironment(), First.class, Second.class, Third.class));

        assertThat(applicationBeans(parse(new StandardEnvironment(), application))).isEqualTo(withoutContexa);
    }

    static Stream<Arguments> orders() {
        return Stream.of(
                Arguments.of("switch first", new Class<?>[]{Switch.class, First.class, Second.class, Third.class}),
                Arguments.of("switch in the middle", new Class<?>[]{First.class, Switch.class, Second.class, Third.class}),
                Arguments.of("switch last", new Class<?>[]{First.class, Second.class, Third.class, Switch.class}));
    }

    /** A bean of the application stops Contexa's of that type wherever the two stand, as the conditions promise. */
    @Test
    void aBeanOfTheApplicationDeclaredWithTheSwitchTakesThePlaceOfContexas() {
        DefaultListableBeanFactory beans = parse(new StandardEnvironment(), SwitchWithOwnBridgeBean.class);

        assertThat(beans.getBeanNamesForType(HostOwnedSecurityChainDiagnostics.class)).containsExactly("applicationDiagnostics");
    }

    /** What auto-configurations evaluate reads what the selector publishes: Contexa's filter of them, its properties. */
    @Test
    void autoConfigurationsSeeContexaActiveAndItsPlatformConfig() {
        DefaultListableBeanFactory beans = parse(new StandardEnvironment(), SwitchBeforeAutoConfiguration.class);

        assertThat(AutoConfigurationStandIn.activeWhenSelected).as("at Spring Boot's auto-configurations").isTrue();
        assertThat(LaterAutoConfigurationStandIn.activeWhenSelected).as("at @ImportAutoConfiguration's").isTrue();
        assertThat(beans.containsBeanDefinition("needsThePlatformConfig"))
                .as("IdentitySecurityCoreAutoConfiguration waits for a PlatformConfig this way").isTrue();
    }

    /** The auto-configuration selector is declared first by @SpringBootApplication: the order must not depend on that. */
    @Test
    void anAutoConfigurationDeclaredAheadOfTheSwitchStillComesAfterIt() {
        parse(new StandardEnvironment(), AutoConfigurationBeforeSwitch.class);

        assertThat(AutoConfigurationStandIn.activeWhenSelected).isTrue();
    }

    /**
     * The real selector of Spring Boot and Contexa's real filter of auto-configurations, on the shape PR-39 measured: an
     * order that put this selector behind them would leave every auto-configuration of Contexa out without a word.
     */
    @Test
    void theRealAutoConfigurationsOfContexaComeInBehindTheApplicationsPlatformConfig() {
        DefaultListableBeanFactory beans = parse(new StandardEnvironment(), RealApplication.class);

        assertThat(beans.getBeanNamesForType(PlatformConfig.class)).containsExactly(APPLICATION_PLATFORM);
        assertThat(beans.containsBeanDefinition(IdentitySecurityCoreAutoConfiguration.class.getName()))
                .as("the identity core waits for a PlatformConfig and for Contexa to be active").isTrue();
    }

    @Test
    void theRealAutoConfigurationsOfContexaStayOutOfAnApplicationThatDoesNotSwitchItOn() {
        DefaultListableBeanFactory beans = parse(new StandardEnvironment(), RealApplicationWithoutSwitch.class);

        assertThat(beans.containsBeanDefinition(IdentitySecurityCoreAutoConfiguration.class.getName())).isFalse();
    }

    @Test
    void anApplicationThatCannotRunContexaIsStillToldWhy() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("application",
                Map.of("spring.main.web-application-type", "reactive")));

        assertThatThrownBy(() -> parse(environment, Switch.class))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .satisfies(refusal -> assertThat(new ContexaOperatingProfileFailureAnalyzer().analyze(refusal))
                        .as("the failure analyzer still says what to do").isNotNull());
    }

    @Test
    void theModeOfTheAnnotationStillReachesTheEnvironment() {
        StandardEnvironment environment = new StandardEnvironment();

        parse(environment, FullSwitch.class);

        assertThat(ContexaPlatformActivation.isActive(environment)).isTrue();
        assertThat(environment.getProperty("contexa.ai.security.mode")).isEqualTo(SecurityMode.FULL.name());
    }

    private DefaultListableBeanFactory parse(StandardEnvironment environment, Class<?>... application) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        new AnnotatedBeanDefinitionReader(beans, environment).register(application);
        ConfigurationClassPostProcessor parser = new ConfigurationClassPostProcessor();
        parser.setEnvironment(environment);
        parser.setResourceLoader(new DefaultResourceLoader());
        parser.setBeanClassLoader(getClass().getClassLoader());
        parser.postProcessBeanDefinitionRegistry(beans);
        return beans;
    }

    private static List<String> applicationBeans(DefaultListableBeanFactory beans) {
        return Arrays.stream(beans.getBeanDefinitionNames())
                .filter(name -> name.startsWith("app"))
                .toList();
    }

    private static PlatformConfig platform() {
        return PlatformConfig.builder().build();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity
    static class Switch {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullSwitch {
    }

    @Configuration(proxyBeanMethods = false)
    static class Declaration {

        @Bean
        PlatformConfig applicationPlatform() {
            return platform();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity
    static class SwitchWithDeclaration {

        @Bean
        PlatformConfig applicationPlatform() {
            return platform();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity
    @Import(Declaration.class)
    static class SwitchImportingDeclaration {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity
    static class SwitchWithNestedDeclaration {

        @Configuration(proxyBeanMethods = false)
        static class Nested {

            @Bean
            PlatformConfig applicationPlatform() {
                return platform();
            }
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity
    static class SwitchWithOwnBridgeBean {

        @Bean
        HostOwnedSecurityChainDiagnostics applicationDiagnostics() {
            return null;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class RealApplication {

        @Bean
        PlatformConfig applicationPlatform() {
            return platform();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    static class RealApplicationWithoutSwitch {

        @Bean
        PlatformConfig applicationPlatform() {
            return platform();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class First {

        @Bean
        String appFirst() {
            return "first";
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Second {

        @Bean
        String appSecond() {
            return "second";
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Third {

        @Bean
        String appThird() {
            return "third";
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAISecurity
    @Import({AutoConfigurationStandIn.class, LaterAutoConfigurationStandIn.class})
    static class SwitchBeforeAutoConfiguration {
    }

    @Configuration(proxyBeanMethods = false)
    @Import(AutoConfigurationStandIn.class)
    @EnableAISecurity
    static class AutoConfigurationBeforeSwitch {
    }

    /** Selects as Spring Boot's auto-configuration selector does, at its order. */
    static class AutoConfigurationStandIn implements DeferredImportSelector, Ordered, EnvironmentAware {

        static Boolean activeWhenSelected;
        private Environment environment;

        @Override
        public String[] selectImports(AnnotationMetadata importingClassMetadata) {
            activeWhenSelected = ContexaPlatformActivation.isActive(environment);
            return new String[]{NeedsThePlatformConfig.class.getName()};
        }

        @Override
        public int getOrder() {
            return new AutoConfigurationImportSelector().getOrder();
        }

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }
    }

    /** Selects at the order of ImportAutoConfigurationImportSelector, one ahead of Spring Boot's. */
    static class LaterAutoConfigurationStandIn implements DeferredImportSelector, Ordered, EnvironmentAware {

        static Boolean activeWhenSelected;
        private Environment environment;

        @Override
        public String[] selectImports(AnnotationMetadata importingClassMetadata) {
            activeWhenSelected = ContexaPlatformActivation.isActive(environment);
            return new String[0];
        }

        @Override
        public int getOrder() {
            return new AutoConfigurationImportSelector().getOrder() - 1;
        }

        @Override
        public void setEnvironment(Environment environment) {
            this.environment = environment;
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class NeedsThePlatformConfig {

        @Bean
        @ConditionalOnBean(PlatformConfig.class)
        @ConditionalOnMissingBean(name = "needsThePlatformConfig")
        String needsThePlatformConfig() {
            return "there";
        }
    }
}
