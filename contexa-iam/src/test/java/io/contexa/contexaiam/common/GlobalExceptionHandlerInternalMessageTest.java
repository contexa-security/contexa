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
package io.contexa.contexaiam.common;

import io.contexa.contexaiam.admin.web.metadata.controller.ResourceAdminController;
import io.contexa.contexaiam.admin.web.metadata.service.ResourceAdminService;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The handler of {@link GlobalExceptionHandler} answers an {@link IllegalArgumentException} with its text. The services
 * of the console refuse with such an exception on purpose, but the JDK's lookup of an enum constant throws one too, and
 * its text names the enum's class: a filter value that is no constant of the resource status reaches the answer as
 * "No enum constant io.contexa...". This reproduces it with the request that does it.
 */
class GlobalExceptionHandlerInternalMessageTest {

    @Disabled("Reproduced: the answer is a 400 whose message is the JDK's \"No enum constant\" followed by the enum's class and the value; enable it once the handler no longer passes the text of such an exception on")
    @Test
    @DisplayName("a status filter that is no constant of the status does not answer with the enum's class")
    void anEnumLookupDoesNotAnswerWithTheClass() throws Exception {
        ResourceAdminService service = new ResourceAdminService(mock(ResourceRegistryService.class),
                mock(ManagedResourceRepository.class), I18nTestSupport.englishMessageSource());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ResourceAdminController(service))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .build();

        MvcResult result = mvc.perform(get("/contexa/admin/workbench/resources").param("status", "BOGUS"))
                .andExpect(status().is4xxClientError())
                .andReturn();

        assertThat(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .doesNotContain("No enum constant", "io.contexa");
    }
}
