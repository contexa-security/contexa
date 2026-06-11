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
package io.contexa.contexaiam.admin.web.monitoring.dto;

public final class SecurityMonitorDtos {

    private SecurityMonitorDtos() {
    }

    public record IpGroupView(String ip, long count, String lastAccess) {

        public static IpGroupView fromRow(Object[] row) {
            return new IpGroupView(valueAt(row, 0), countAt(row), valueAt(row, 2));
        }

        public String getIp() {
            return ip;
        }

        public long getCount() {
            return count;
        }

        public String getLastAccess() {
            return lastAccess;
        }

        private static long countAt(Object[] row) {
            if (row == null || row.length <= 1 || row[1] == null) {
                return 0L;
            }
            if (row[1] instanceof Number number) {
                return number.longValue();
            }
            return Long.parseLong(row[1].toString());
        }

        private static String valueAt(Object[] row, int index) {
            if (row == null || row.length <= index || row[index] == null) {
                return "";
            }
            return row[index].toString();
        }
    }
}
