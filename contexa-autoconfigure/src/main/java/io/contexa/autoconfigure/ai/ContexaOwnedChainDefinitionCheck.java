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
package io.contexa.autoconfigure.ai;

import io.contexa.autoconfigure.identity.IdentitySecurityCoreContexaOwnedConfiguration;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.asm.ClassReader;
import org.springframework.asm.ClassVisitor;
import org.springframework.asm.Handle;
import org.springframework.asm.Label;
import org.springframework.asm.MethodVisitor;
import org.springframework.asm.Opcodes;
import org.springframework.asm.SpringAsmInfo;
import org.springframework.asm.Type;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConstructorArgumentValues;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.core.env.Environment;
import org.springframework.core.type.MethodMetadata;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Where Contexa owns the sign-in, the start of an application that declares a security chain of its own is refused
 * ({@link OwnershipStartupDiagnostics}). That refusal looks at the built chains, so it comes once every bean exists: after
 * Contexa has connected to its database and installed its schema there, which is the application's database when the
 * two share one. This refuses the same start before any bean exists, from the bean definitions alone, and so leaves
 * nothing behind.
 * <p>
 * A bean definition does not say what its chain will hold, so this refuses only a chain it can be certain of, one the
 * later refusal refuses as well: a bean method of the application whose every {@code return} hands back what an
 * {@link HttpSecurity} of Spring Security builds. Spring Security puts a filter in every one it hands out, and a chain with
 * filters, other than Contexa's own, is what the later refusal refuses. Whatever this cannot be certain of (a chain
 * registered in code, built in another method or returned on a condition) it leaves to the later refusal, which decides
 * as before. It never refuses a start that the later refusal lets through, and a failure of its own reading lets the
 * start go on.
 */
public final class ContexaOwnedChainDefinitionCheck implements BeanFactoryPostProcessor, PriorityOrdered, EnvironmentAware {

    /** The bean Spring Security hands every chain method its {@link HttpSecurity} from. */
    static final String SPRING_HTTP_SECURITY =
            "org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration.httpSecurity";
    /** Contexa's own customizer, which only leaves the static resources out. */
    private static final String CONTEXA_WEB_SECURITY_CUSTOMIZER = "contexaWebSecurityCustomizer";
    /** The bean of the later refusal, as {@link AiSecurityConfiguration} declares it. */
    static final String LATER_REFUSAL = "contexaOwnershipStartupDiagnostics";
    /** What Spring Security puts around its chain proxy; both give the later refusal the chains, also behind the debug filter. */
    static final Set<String> SPRING_COMPOSITES = Set.of(
            "org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration$CompositeFilterChainProxy",
            "org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration$CompositeFilterChainProxy");
    private static final int MOST_WRAPPERS = 4;

    private static final String HTTP_SECURITY = Type.getInternalName(HttpSecurity.class);
    private static final String HTTP_SECURITY_DESCRIPTOR = Type.getDescriptor(HttpSecurity.class);
    private static final Set<String> CHAIN_TYPES =
            Set.of(Type.getInternalName(SecurityFilterChain.class), Type.getInternalName(DefaultSecurityFilterChain.class));
    private static final String BUILD = "build";
    private static final String BUILD_DESCRIPTOR = "()Ljava/lang/Object;";
    private static final int LABEL = -1;

    private Environment environment;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        List<String> chains;
        try {
            if (environment == null
                    || ContexaOperatingProfile.resolve(environment).ownership() != SecurityOwnershipMode.CONTEXA_OWNED) {
                return;
            }
            chains = certainApplicationChains(beanFactory);
        } catch (RuntimeException | IOException | LinkageError e) {
            // what cannot be read is left to the later refusal, which decides on the built chains
            return;
        }
        if (!chains.isEmpty()) {
            throw OwnershipStartupDiagnostics.applicationChainsRefused(chains);
        }
    }

    /** The chains of the application, by bean name, that the later refusal is certain to refuse. */
    static List<String> certainApplicationChains(ConfigurableListableBeanFactory beans) throws IOException {
        Boolean seesThroughDebug = springChainProxySeesThroughDebug(beans);
        if (seesThroughDebug == null || !laterRefusalIsContexas(beans) || !onlySpringHandsOutHttpSecurity(beans)
                || (!seesThroughDebug && debugFilterMayHideTheChains(beans))) {
            return List.of();
        }
        List<String> chains = new ArrayList<>();
        for (String name : beans.getBeanNamesForType(SecurityFilterChain.class, true, false)) {
            if (certainChain(beans, name)) {
                chains.add(name);
            }
        }
        return chains;
    }

    private static boolean composite(BeanDefinition definition) {
        String type = definition.getBeanClassName();
        return type != null && SPRING_COMPOSITES.contains(type);
    }

    /** An application may put a bean of its own in place of the later refusal; what that one does is not known here. */
    private static boolean laterRefusalIsContexas(ConfigurableListableBeanFactory beans) {
        if (!beans.containsBeanDefinition(LATER_REFUSAL)) {
            return false;
        }
        BeanDefinition definition = beans.getBeanDefinition(LATER_REFUSAL);
        MethodMetadata method = definition instanceof AnnotatedBeanDefinition annotated ? annotated.getFactoryMethodMetadata() : null;
        return method != null && AiSecurityConfiguration.class.getName().equals(method.getDeclaringClassName());
    }

    /**
     * The chain beans reach the requests, and the later refusal, through the chain proxy that Spring Security's own bean
     * method makes: whether a composite of Spring Security is around it, which gives the chains also behind the debug
     * filter, or nothing is; null when the proxy is another.
     */
    @Nullable
    static Boolean springChainProxySeesThroughDebug(ConfigurableListableBeanFactory beans) {
        String[] configurations = beans.getBeanNamesForType(WebSecurityConfiguration.class, false, false);
        String proxy = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME;
        if (configurations.length != 1 || !beans.containsBeanDefinition(proxy)) {
            return null;
        }
        BeanDefinition definition = beans.getBeanDefinition(proxy);
        for (int wrappers = 0; wrappers <= MOST_WRAPPERS && definition != null; wrappers++) {
            if (configurations[0].equals(definition.getFactoryBeanName()) && proxy.equals(definition.getFactoryMethodName())) {
                return wrappers > 0;
            }
            definition = composite(definition) ? wrapped(definition) : null;
        }
        return null;
    }

    /** The one definition among the filters of a composite that is a chain proxy of Spring Security, or a composite again. */
    @Nullable
    private static BeanDefinition wrapped(BeanDefinition composite) {
        ConstructorArgumentValues.ValueHolder filters = composite.getConstructorArgumentValues().getIndexedArgumentValue(0, List.class);
        if (filters == null || !(filters.getValue() instanceof List<?> list)) {
            return null;
        }
        BeanDefinition found = null;
        for (Object filter : list) {
            if (filter instanceof BeanDefinition candidate && (composite(candidate)
                    || AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME.equals(candidate.getFactoryMethodName()))) {
                if (found != null) {
                    return null;
                }
                found = candidate;
            }
        }
        return found;
    }

    /** The {@link HttpSecurity} a chain method is given is the one Spring Security fills with its filters. */
    private static boolean onlySpringHandsOutHttpSecurity(ConfigurableListableBeanFactory beans) {
        return Arrays.equals(beans.getBeanNamesForType(HttpSecurity.class, true, false), new String[]{SPRING_HTTP_SECURITY});
    }

    /**
     * With its debug filter on and no composite around it, Spring Security's chain proxy is wrapped, and the later refusal
     * does not see the chains. The annotation can switch it on, and so can any customizer or configurer of the web security.
     */
    private static boolean debugFilterMayHideTheChains(ConfigurableListableBeanFactory beans) {
        List<String> customizers = new ArrayList<>(Arrays.asList(beans.getBeanNamesForType(WebSecurityCustomizer.class, true, false)));
        customizers.addAll(Arrays.asList(beans.getBeanNamesForType(WebSecurityConfigurer.class, true, false)));
        customizers.remove(CONTEXA_WEB_SECURITY_CUSTOMIZER);
        if (!customizers.isEmpty()) {
            return true;
        }
        for (String name : beans.getBeanDefinitionNames()) {
            if (beans.getBeanDefinition(name) instanceof AnnotatedBeanDefinition annotated) {
                Map<String, Object> enabled = annotated.getMetadata().getAnnotationAttributes(EnableWebSecurity.class.getName());
                if (enabled != null && !Boolean.FALSE.equals(enabled.get("debug"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** A bean method of the application whose every return is what an {@link HttpSecurity} of Spring Security builds. */
    private static boolean certainChain(ConfigurableListableBeanFactory beans, String name) throws IOException {
        if (IdentitySecurityCoreContexaOwnedConfiguration.PLACEHOLDER_CHAIN.equals(name) || !beans.containsBeanDefinition(name)) {
            return false;
        }
        BeanDefinition definition = beans.getBeanDefinition(name);
        BeanDefinition merged = beans.getMergedBeanDefinition(name);
        MethodMetadata method = definition instanceof AnnotatedBeanDefinition annotated ? annotated.getFactoryMethodMetadata() : null;
        // a chain the proxy is not given is not refused later either
        if (method == null || merged.isAbstract() || !merged.isAutowireCandidate()
                || (merged instanceof AbstractBeanDefinition candidate && !candidate.isDefaultCandidate())
                || !method.getMethodName().equals(merged.getFactoryMethodName())) {
            return false;
        }
        Class<?> factory = merged.getFactoryBeanName() != null
                ? beans.getType(merged.getFactoryBeanName(), false)
                : ClassUtils.resolveClassName(merged.getBeanClassName(), beans.getBeanClassLoader());
        return factory != null && returnsOnlyWhatHttpSecurityBuilds(ClassUtils.getUserClass(factory),
                method.getDeclaringClassName(), method.getMethodName());
    }

    /**
     * The method is read in the class that declares it; it must be the only method of its name from the class of the
     * factory up to that one, so that no override or overload of it is what Spring calls.
     */
    static boolean returnsOnlyWhatHttpSecurityBuilds(Class<?> factory, String declaringClass, String methodName) throws IOException {
        int found = 0;
        MethodReader declared = null;
        for (Class<?> type = factory; type != null && type != Object.class; type = type.getSuperclass()) {
            MethodReader reader = read(type, methodName);
            if (reader == null) {
                return false;
            }
            found += reader.found;
            if (type.getName().equals(declaringClass)) {
                declared = reader;
                break;
            }
        }
        return declared != null && found == 1 && returnsOnlyWhatHttpSecurityBuilds(declared.access, declared.descriptor,
                declared.instructions);
    }

    private static MethodReader read(Class<?> type, String methodName) throws IOException {
        ClassLoader loader = type.getClassLoader() != null ? type.getClassLoader() : ClassUtils.getDefaultClassLoader();
        String resource = ClassUtils.convertClassNameToResourcePath(type.getName()) + ClassUtils.CLASS_FILE_SUFFIX;
        try (InputStream bytes = loader != null ? loader.getResourceAsStream(resource) : null) {
            if (bytes == null) {
                return null;
            }
            MethodReader reader = new MethodReader(methodName);
            new ClassReader(bytes).accept(reader, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            return reader;
        }
    }

    /**
     * Every {@code return} hands back, right as it is built, a chain of an {@link HttpSecurity}, with no jump landing in
     * between; and every {@link HttpSecurity} of the method is the one it was given, or that one returned by its own
     * methods (all of them return it), never one made, cast, read from a field or returned by another type.
     */
    static boolean returnsOnlyWhatHttpSecurityBuilds(int access, String descriptor, List<Instruction> code) {
        if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                || !CHAIN_TYPES.contains(Type.getReturnType(descriptor).getInternalName())) {
            return false;
        }
        for (Type parameter : Type.getArgumentTypes(descriptor)) {
            if (parameter.getSort() == Type.ARRAY && parameter.getDescriptor().contains(HTTP_SECURITY_DESCRIPTOR)) {
                return false;
            }
        }
        boolean returns = false;
        for (int i = 0; i < code.size(); i++) {
            Instruction instruction = code.get(i);
            switch (instruction.opcode()) {
                case Opcodes.ARETURN -> {
                    if (i < 2 || !builds(code.get(i - 2)) || !castsToAChain(code.get(i - 1))) {
                        return false;
                    }
                    returns = true;
                }
                case Opcodes.CHECKCAST -> {
                    if (namesHttpSecurity(instruction.owner())
                            || (CHAIN_TYPES.contains(instruction.owner()) && (i == 0 || !builds(code.get(i - 1))))) {
                        return false;
                    }
                }
                case Opcodes.NEW -> {
                    if (namesHttpSecurity(instruction.owner())) {
                        return false;
                    }
                }
                case Opcodes.GETFIELD, Opcodes.GETSTATIC -> {
                    if (instruction.descriptor().contains(HTTP_SECURITY_DESCRIPTOR)) {
                        return false;
                    }
                }
                case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL, Opcodes.INVOKESTATIC, Opcodes.INVOKEINTERFACE,
                     Opcodes.INVOKEDYNAMIC -> {
                    String returned = Type.getReturnType(instruction.descriptor()).getDescriptor();
                    boolean itsOwn = instruction.opcode() == Opcodes.INVOKEVIRTUAL && HTTP_SECURITY.equals(instruction.owner())
                            && HTTP_SECURITY_DESCRIPTOR.equals(returned);
                    if (returned.contains(HTTP_SECURITY_DESCRIPTOR) && !itsOwn) {
                        return false;
                    }
                }
                default -> {
                }
            }
        }
        return returns;
    }

    private static boolean builds(Instruction instruction) {
        return instruction.opcode() == Opcodes.INVOKEVIRTUAL && HTTP_SECURITY.equals(instruction.owner())
                && BUILD.equals(instruction.name()) && BUILD_DESCRIPTOR.equals(instruction.descriptor());
    }

    private static boolean castsToAChain(Instruction instruction) {
        return instruction.opcode() == Opcodes.CHECKCAST && CHAIN_TYPES.contains(instruction.owner());
    }

    private static boolean namesHttpSecurity(String type) {
        return HTTP_SECURITY.equals(type) || type.contains(HTTP_SECURITY_DESCRIPTOR);
    }

    /** One instruction as ASM visits it; a label, which a jump may land on, is an instruction of its own here. */
    record Instruction(int opcode, String owner, String name, String descriptor) {

        static Instruction of(int opcode) {
            return new Instruction(opcode, "", "", "");
        }
    }

    /** The methods of one name in one class: how many there are, and the instructions of the first. */
    static final class MethodReader extends ClassVisitor {

        private final String wanted;
        int found;
        int access;
        String descriptor;
        final List<Instruction> instructions = new ArrayList<>();

        MethodReader(String wanted) {
            super(SpringAsmInfo.ASM_VERSION);
            this.wanted = wanted;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (!wanted.equals(name) || ++found > 1) {
                return null;
            }
            this.access = access;
            this.descriptor = descriptor;
            return new MethodVisitor(SpringAsmInfo.ASM_VERSION) {

                @Override
                public void visitInsn(int opcode) {
                    instructions.add(Instruction.of(opcode));
                }

                @Override
                public void visitIntInsn(int opcode, int operand) {
                    instructions.add(Instruction.of(opcode));
                }

                @Override
                public void visitVarInsn(int opcode, int variable) {
                    instructions.add(Instruction.of(opcode));
                }

                @Override
                public void visitTypeInsn(int opcode, String type) {
                    instructions.add(new Instruction(opcode, type, "", ""));
                }

                @Override
                public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                    instructions.add(new Instruction(opcode, owner, name, descriptor));
                }

                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                    instructions.add(new Instruction(opcode, owner, name, descriptor));
                }

                @Override
                public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrap, Object... arguments) {
                    instructions.add(new Instruction(Opcodes.INVOKEDYNAMIC, "", name, descriptor));
                }

                @Override
                public void visitJumpInsn(int opcode, Label label) {
                    instructions.add(Instruction.of(opcode));
                }

                @Override
                public void visitLabel(Label label) {
                    instructions.add(Instruction.of(LABEL));
                }

                @Override
                public void visitLdcInsn(Object value) {
                    instructions.add(Instruction.of(Opcodes.LDC));
                }

                @Override
                public void visitIincInsn(int variable, int increment) {
                    instructions.add(Instruction.of(Opcodes.IINC));
                }

                @Override
                public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
                    instructions.add(Instruction.of(Opcodes.TABLESWITCH));
                }

                @Override
                public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
                    instructions.add(Instruction.of(Opcodes.LOOKUPSWITCH));
                }

                @Override
                public void visitMultiANewArrayInsn(String descriptor, int dimensions) {
                    instructions.add(new Instruction(Opcodes.MULTIANEWARRAY, descriptor, "", descriptor));
                }
            };
        }
    }
}
