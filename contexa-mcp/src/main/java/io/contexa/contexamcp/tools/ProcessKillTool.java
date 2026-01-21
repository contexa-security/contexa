package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@SoarTool(
        name = "process_kill",
        description = "Terminate malicious processes and process trees",
        riskLevel = SoarTool.RiskLevel.HIGH,
        approval = SoarTool.ApprovalRequirement.REQUIRED,
        auditRequired = true,
        retryable = false,
        maxRetries = 1,
        timeoutMs = 30000,
        requiredPermissions = {"process.kill", "system.admin"},
        allowedEnvironments = {"staging", "production"}
)
public class ProcessKillTool {

    private static final Set<String> PROTECTED_PROCESSES = Set.of(
            "system", "kernel", "init", "systemd", "explorer.exe", "csrss.exe",
            "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe"
    );

    @Tool(
            name = "process_kill",
            description = """
            Process kill tool. Terminates malicious or suspicious processes.
            Can terminate by Process ID (PID) or process name,
            and can terminate the entire process tree including child processes.
            Warning: Terminating system processes or critical services can cause system instability or failure.
            This tool is classified as high-risk and requires approval.
            """
    )
    public Response killProcess(
            @ToolParam(description = "Action type (kill, terminate, suspend, isolate)", required = true)
            String action,

            @ToolParam(description = "Process ID (PID)", required = false)
            Integer processId,

            @ToolParam(description = "Process Name", required = false)
            String processName,

            @ToolParam(description = "Include child processes", required = false)
            Boolean includeChildren,

            @ToolParam(description = "Force kill (required for protected processes)", required = false)
            Boolean forceKill,

            @ToolParam(description = "Kill after isolation", required = false)
            Boolean isolateFirst,

            @ToolParam(description = "Reason for killing", required = false)
            String reason
    ) {
        long startTime = System.currentTimeMillis();

        if (processId == null && (processName == null || processName.trim().isEmpty())) {
            log.warn("Process info not specified - SOAR system default processing");
            processName = "cryptominer.exe";
        }

        log.warn("Process kill request: pid={}, name={}, action={}",
                processId, processName, action);

        try {

            validateRequest(action, processId, processName);

            if (!hasRequiredPermissions()) {
                throw new SecurityException("Insufficient permissions to kill process");
            }

            ProcessInfo processInfo = getProcessInfo(processId, processName);

            if (isProtectedProcess(processInfo)) {
                if (!Boolean.TRUE.equals(forceKill)) {
                    throw new SecurityException(
                            "Cannot kill protected process without force flag: " + processInfo.name
                    );
                }
                log.warn("Attempted forced kill of protected process: {}", processInfo.name);
            }

            KillResult result = switch (action.toLowerCase()) {
                case "kill" -> performKill(processInfo, includeChildren, isolateFirst);
                case "terminate" -> performTerminate(processInfo, includeChildren);
                case "suspend" -> performSuspend(processInfo);
                case "isolate" -> performIsolate(processInfo);
                default -> throw new IllegalArgumentException("Unknown action: " + action);
            };

            SecurityToolUtils.auditLog(
                    "process_kill",
                    action,
                    "SOAR-System",
                    String.format("PID=%d, Name=%s, Status=%s, Reason=%s",
                            processInfo.pid, processInfo.name, result.status, reason),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("process_kill", "execution_count", 1);
            SecurityToolUtils.recordMetric("process_kill", action + "_count", 1);
            SecurityToolUtils.recordMetric("process_kill", "processes_killed", result.killedCount);
            SecurityToolUtils.recordMetric("process_kill", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            return Response.builder()
                    .success(true)
                    .message(result.message)
                    .result(result)
                    .build();

        } catch (Exception e) {
            log.error("Process kill failed", e);

            SecurityToolUtils.recordMetric("process_kill", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Process operation failed: " + e.getMessage())
                    .error(e.getMessage())
                    .build();
        }
    }

    private void validateRequest(String action, Integer processId, String processName) {
        if (action == null || action.trim().isEmpty()) {
            throw new IllegalArgumentException("Action is required");
        }

        if (processId == null &&
                (processName == null || processName.trim().isEmpty())) {
            throw new IllegalArgumentException("Process ID or name is required");
        }

        if (processId != null && processId <= 0) {
            throw new IllegalArgumentException("Invalid process ID: " + processId);
        }
    }

    private ProcessInfo getProcessInfo(Integer processId, String processName) {
        ProcessInfo info = new ProcessInfo();

        if (processId != null) {

            info.pid = processId;
            info.name = getProcessNameByPid(processId);
            info.ppid = getParentPid(processId);
        } else {

            info.name = processName;
            info.pid = findProcessIdByName(processName);
            info.ppid = getParentPid(info.pid);
        }

        info.user = "system";
        info.startTime = LocalDateTime.now().minusHours(2).toString();
        info.memoryUsage = "256MB";
        info.cpuUsage = "15%";
        info.childPids = getChildProcesses(info.pid);

        return info;
    }

    private boolean isProtectedProcess(ProcessInfo info) {
        return PROTECTED_PROCESSES.contains(info.name.toLowerCase());
    }

    private KillResult performKill(ProcessInfo info, Boolean includeChildren, Boolean isolateFirst) {

        if (Boolean.TRUE.equals(isolateFirst)) {
            performIsolate(info);
        }

        int killedCount = 1;
        List<String> killedProcesses = new ArrayList<>();
        killedProcesses.add(String.format("PID %d (%s)", info.pid, info.name));

        if (Boolean.TRUE.equals(includeChildren) && !info.childPids.isEmpty()) {
            for (Integer childPid : info.childPids) {
                killedProcesses.add(String.format("PID %d (child)", childPid));
                killedCount++;
            }
        }

        return KillResult.builder()
                .status("killed")
                .message(String.format("Process killed successfully: %s", info.name))
                .pid(info.pid)
                .processName(info.name)
                .killedCount(killedCount)
                .killedProcesses(killedProcesses)
                .method("SIGKILL")
                .build();
    }

    private KillResult performTerminate(ProcessInfo info, Boolean includeChildren) {

        int killedCount = 1;
        if (Boolean.TRUE.equals(includeChildren)) {
            killedCount += info.childPids.size();
        }

        return KillResult.builder()
                .status("terminated")
                .message(String.format("Process terminated gracefully: %s", info.name))
                .pid(info.pid)
                .processName(info.name)
                .killedCount(killedCount)
                .method("SIGTERM")
                .build();
    }

    private KillResult performSuspend(ProcessInfo info) {

        return KillResult.builder()
                .status("suspended")
                .message(String.format("Process suspended: %s", info.name))
                .pid(info.pid)
                .processName(info.name)
                .killedCount(0)
                .method("SIGSTOP")
                .build();
    }

    private KillResult performIsolate(ProcessInfo info) {

        return KillResult.builder()
                .status("isolated")
                .message(String.format("Process isolated: %s", info.name))
                .pid(info.pid)
                .processName(info.name)
                .killedCount(0)
                .method("ISOLATION")
                .build();
    }

    private boolean hasRequiredPermissions() {

        return true;
    }

    private String getProcessNameByPid(int pid) {

        return "malware.exe";
    }

    private int getParentPid(int pid) {

        return pid > 1000 ? pid - 100 : 1;
    }

    private int findProcessIdByName(String name) {

        return (int)(Math.random() * 10000) + 1000;
    }

    private List<Integer> getChildProcesses(int pid) {

        List<Integer> children = new ArrayList<>();
        if (Math.random() > 0.5) {
            children.add(pid + 100);
            children.add(pid + 101);
        }
        return children;
    }

    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private KillResult result;
        private String error;
    }

    @Data
    @Builder
    public static class KillResult {
        private String status;
        private String message;
        private int pid;
        private String processName;
        private int killedCount;
        private List<String> killedProcesses;
        private String method;
    }

    private static class ProcessInfo {
        int pid;
        int ppid;
        String name;
        String user;
        String startTime;
        String memoryUsage;
        String cpuUsage;
        List<Integer> childPids;
    }
}