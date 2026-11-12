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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.core.type.MethodMetadata;
import org.springframework.lang.Nullable;
import org.springframework.mail.MailSender;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Contexa brings the mail classes with it, and settings that name a mail server for its code mails make Spring Boot add a
 * {@code mail} health, which asks that server on every health call and waits for its answer without a limit. In an application
 * that sends no mail of its own, a mail server only Contexa uses would so decide, and while it is silent hold, the health a
 * platform restarts the application on. That health is taken out again; where the application mails, names the health in its
 * settings, or has a sender or a mail health of its own, nothing is touched.
 */
@Slf4j
final class HostHealthWithoutContexaMail implements SmartInitializingSingleton {

    static final String MAIL_HEALTH = "mail";

    private static final String MAIL_HEALTH_SETTING = "management.health.mail.enabled";
    private static final String HEALTH_GROUPS = "management.endpoint.health.group";
    private static final String MAIL_HEALTH_BEAN = "mailHealthContributor";
    private static final String SENDER_OF_SPRING_BOOT = "org.springframework.boot.autoconfigure.mail.";
    private static final String MAIL_HEALTH_OF_SPRING_BOOT =
            "org.springframework.boot.actuate.autoconfigure.mail.MailHealthContributorAutoConfiguration";
    private static final String CONTEXA = "io.contexa.";
    private static final String SPRING_BOOT = "org.springframework.boot.";

    @Nullable
    private final HealthContributorRegistry registry;
    private final ConfigurableListableBeanFactory beans;
    private final Environment environment;

    HostHealthWithoutContexaMail(@Nullable HealthContributorRegistry registry, ConfigurableListableBeanFactory beans,
                                 Environment environment) {
        this.registry = registry;
        this.beans = beans;
        this.environment = environment;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (registry == null || environment.containsProperty(MAIL_HEALTH_SETTING)) {
            return;
        }
        String sender = theOneSenderSpringBootMadeOfTheSettings();
        if (sender == null || !springBootAddedTheMailHealth() || theApplicationMails(sender) || aHealthGroupNamesMail()) {
            return;
        }
        registry.unregisterContributor(MAIL_HEALTH);
        log.info("[Contexa] The 'mail' health is left out of this application's health: only Contexa uses the mail server "
                + "the settings name, and that health waits for the server without a limit. Set "
                + "management.health.mail.enabled=true to keep it.");
    }

    @Nullable
    private String theOneSenderSpringBootMadeOfTheSettings() {
        String[] senders = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beans, MailSender.class, true, false);
        return senders.length == 1 && declaredBy(senders[0], SENDER_OF_SPRING_BOOT) ? senders[0] : null;
    }

    /** One indicator Spring Boot made, and the very one under the name: a health of the application's is not Contexa's to take. */
    private boolean springBootAddedTheMailHealth() {
        if (!declaredBy(MAIL_HEALTH_BEAN, MAIL_HEALTH_OF_SPRING_BOOT)) {
            return false;
        }
        Object made = beans.getSingleton(MAIL_HEALTH_BEAN);
        return made instanceof HealthIndicator && made == registry.getContributor(MAIL_HEALTH);
    }

    /** A bean that had the sender handed to it; one whose type cannot be told counts as the application's. */
    private boolean theApplicationMails(String sender) {
        return Arrays.stream(beans.getDependentBeans(sender)).anyMatch(dependent -> ofTheApplication(typeOf(dependent)));
    }

    @Nullable
    private Class<?> typeOf(String bean) {
        try {
            return beans.getType(bean);
        } catch (RuntimeException unknown) {
            return null;
        }
    }

    /** A group that names the health needs it there: Spring Boot refuses to start on a group member it cannot find. */
    private boolean aHealthGroupNamesMail() {
        Map<String, GroupMembers> groups;
        try {
            groups = Binder.get(environment).bind(HEALTH_GROUPS, Bindable.mapOf(String.class, GroupMembers.class))
                    .orElse(Map.of());
        } catch (RuntimeException unreadable) {
            return true;
        }
        return groups.values().stream()
                .flatMap(group -> Stream.concat(group.getInclude().stream(), group.getExclude().stream()))
                .anyMatch(HostHealthWithoutContexaMail::isTheMailHealth);
    }

    private static boolean isTheMailHealth(@Nullable String member) {
        if (member == null) {
            return false;
        }
        String name = member.trim().toLowerCase(Locale.ROOT);
        return name.equals(MAIL_HEALTH) || name.startsWith(MAIL_HEALTH + "/");
    }

    private boolean declaredBy(String bean, String source) {
        if (!beans.containsBeanDefinition(bean) || !(beans.getBeanDefinition(bean) instanceof AnnotatedBeanDefinition annotated)) {
            return false;
        }
        MethodMetadata factoryMethod = annotated.getFactoryMethodMetadata();
        return factoryMethod != null && factoryMethod.getDeclaringClassName().startsWith(source);
    }

    /** Whether a bean of this type is the application's: anything that is neither Contexa's nor Spring Boot's own. */
    static boolean ofTheApplication(@Nullable Class<?> type) {
        if (type == null) {
            return true;
        }
        String name = type.getName();
        return !name.startsWith(CONTEXA) && !name.startsWith(SPRING_BOOT);
    }

    /** The members a health group of the settings names. */
    static final class GroupMembers {

        private Set<String> include = new LinkedHashSet<>();
        private Set<String> exclude = new LinkedHashSet<>();

        public Set<String> getInclude() {
            return include;
        }

        public void setInclude(@Nullable Set<String> include) {
            this.include = include == null ? new LinkedHashSet<>() : include;
        }

        public Set<String> getExclude() {
            return exclude;
        }

        public void setExclude(@Nullable Set<String> exclude) {
            this.exclude = exclude == null ? new LinkedHashSet<>() : exclude;
        }
    }
}
