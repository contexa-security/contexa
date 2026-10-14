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
package io.contexa.contexacore.autonomous.context.support;

import org.springframework.lang.Nullable;

import java.time.LocalDateTime;

/**
 * The past allowed records of one path template, path and HTTP method in a past record scope (W3-18): how many and the
 * latest time, on the event clock the records were stored with.
 *
 * @param pathFamily the path template, null when the records do not state one
 * @param path       the request path, null when the records do not state one
 * @param httpMethod the HTTP method, null when the records do not state one
 * @param records    how many records
 * @param latest     the latest record time, null when none states one
 */
public record PastRecordGroup(@Nullable String pathFamily, @Nullable String path, @Nullable String httpMethod,
                              long records, @Nullable LocalDateTime latest) {
}
