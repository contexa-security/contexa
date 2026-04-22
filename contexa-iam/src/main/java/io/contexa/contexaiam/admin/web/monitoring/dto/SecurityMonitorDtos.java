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
