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
package io.contexa.contexaidentity.security.core.bootstrap;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;

@Slf4j
public class WebSecurityConfigurationDependencyInjector implements BeanFactoryPostProcessor {

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        
        try {
            
            String[] webSecurityConfigNames = beanFactory.getBeanNamesForType(
                    WebSecurityConfiguration.class, false, false);

            if (webSecurityConfigNames.length == 0) {
                log.warn("WebSecurityConfiguration bean not found. Dependency injection skipped.");
                return;
            }

            for (String beanName : webSecurityConfigNames) {
                BeanDefinition bd = beanFactory.getBeanDefinition(beanName);

                String[] existingDependsOn = bd.getDependsOn();

                String[] newDependsOn;
                if (existingDependsOn == null || existingDependsOn.length == 0) {
                    newDependsOn = new String[]{"platformBootstrap"};
                } else {
                    
                    boolean alreadyExists = false;
                    for (String dep : existingDependsOn) {
                        if ("platformBootstrap".equals(dep)) {
                            alreadyExists = true;
                            break;
                        }
                    }

                    if (!alreadyExists) {
                        newDependsOn = new String[existingDependsOn.length + 1];
                        System.arraycopy(existingDependsOn, 0, newDependsOn, 0, existingDependsOn.length);
                        newDependsOn[existingDependsOn.length] = "platformBootstrap";
                    } else {
                        newDependsOn = existingDependsOn;
                    }
                }

                bd.setDependsOn(newDependsOn);
                            }

        } catch (Exception e) {
            log.error("Failed to add dependency to WebSecurityConfiguration", e);
            throw new RuntimeException("Failed to configure WebSecurityConfiguration dependency", e);
        }
    }
}
