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
package io.contexa.springbootstartercontexa;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Entry point of the standalone Contexa platform image built from this module (see the repository Dockerfile).
 *
 * <p>This class ships inside the starter library jar, so it intentionally carries no stereotype annotation
 * such as {@code @SpringBootApplication} or {@code @Configuration}. Host applications that depend on the
 * starter and component-scan {@code io.contexa} therefore never pick it up, and its {@code @EnableAISecurity}
 * only takes effect when this class is the primary source passed to {@link SpringApplication}.</p>
 */
@EnableAutoConfiguration
@EnableAISecurity(mode = SecurityMode.FULL)
public class SpringBootStarterContexaApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootStarterContexaApplication.class, args);
    }

}