package io.contexa.contexamcp.completions;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.*;


@Slf4j
@RequiredArgsConstructor
public class SecurityCommandCompletion {
    
    
    private static final Map<String, List<CommandInfo>> SECURITY_COMMANDS = new HashMap<>();
    
    static {
        
        SECURITY_COMMANDS.put("scan", List.of(
            new CommandInfo("scan network", "Scan network for open ports and services", "scan network --range 192.168.1.0/24 --ports 1-65535"),
            new CommandInfo("scan port", "Scan specific ports on target", "scan port --target <IP> --ports 80,443,8080"),
            new CommandInfo("scan vulnerability", "Scan for known vulnerabilities", "scan vulnerability --target <IP> --depth full"),
            new CommandInfo("scan service", "Identify running services", "scan service --target <IP> --detect-version")
        ));
        
        
        SECURITY_COMMANDS.put("analyze", List.of(
            new CommandInfo("analyze logs", "Analyze security logs for threats", "analyze logs --type security --severity high"),
            new CommandInfo("analyze traffic", "Analyze network traffic patterns", "analyze traffic --interface eth0 --duration 1h"),
            new CommandInfo("analyze behavior", "Analyze user behavior for anomalies", "analyze behavior --user <username> --period 7d"),
            new CommandInfo("analyze malware", "Analyze potential malware samples", "analyze malware --file <path> --sandbox true")
        ));
        
        
        SECURITY_COMMANDS.put("block", List.of(
            new CommandInfo("block ip", "Block malicious IP address", "block ip --address <IP> --duration permanent"),
            new CommandInfo("block port", "Block network port", "block port --number <port> --protocol tcp/udp"),
            new CommandInfo("block user", "Block user account", "block user --username <user> --reason <reason>"),
            new CommandInfo("block process", "Block malicious process", "block process --name <process> --kill true")
        ));
        
        
        SECURITY_COMMANDS.put("isolate", List.of(
            new CommandInfo("isolate host", "Isolate compromised host", "isolate host --target <IP> --level full"),
            new CommandInfo("isolate network", "Isolate network segment", "isolate network --segment <VLAN> --duration 1h"),
            new CommandInfo("isolate file", "Quarantine suspicious file", "isolate file --path <file> --backup true"),
            new CommandInfo("isolate process", "Isolate running process", "isolate process --pid <PID> --sandbox true")
        ));
        
        
        SECURITY_COMMANDS.put("investigate", List.of(
            new CommandInfo("investigate incident", "Investigate security incident", "investigate incident --id <incident_id> --depth full"),
            new CommandInfo("investigate user", "Investigate user activities", "investigate user --username <user> --period 30d"),
            new CommandInfo("investigate file", "Investigate file integrity", "investigate file --path <file> --hash-check true"),
            new CommandInfo("investigate connection", "Investigate network connection", "investigate connection --src <IP> --dst <IP>")
        ));
        
        
        SECURITY_COMMANDS.put("report", List.of(
            new CommandInfo("report generate", "Generate security report", "report generate --type executive --format pdf"),
            new CommandInfo("report incident", "Generate incident report", "report incident --id <incident_id> --details full"),
            new CommandInfo("report compliance", "Generate compliance report", "report compliance --standard PCI-DSS --period quarterly"),
            new CommandInfo("report vulnerability", "Generate vulnerability report", "report vulnerability --severity critical,high")
        ));
    }
    
    
    public Map<String, Object> createCompletionSpecification() {
        log.info("🔤 보안 명령어 자동 완성 Specification 생성");
        
        Map<String, Object> specification = new HashMap<>();
        specification.put("name", "security_commands");
        specification.put("description", "Security command auto-completion for contexa platform");
        specification.put("version", "1.0.0");
        specification.put("commandCount", SECURITY_COMMANDS.size());
        specification.put("totalCommands", SECURITY_COMMANDS.values().stream()
            .mapToInt(List::size)
            .sum());
        
        
        specification.put("categories", new ArrayList<>(SECURITY_COMMANDS.keySet()));
        
        
        List<CompletionItem> sampleCompletions = generateCompletions("scan");
        specification.put("sampleCompletions", sampleCompletions);
        
        log.info("보안 명령어 자동 완성 Specification 생성 완료: {} 카테고리, {} 명령어", 
                SECURITY_COMMANDS.size(), 
                SECURITY_COMMANDS.values().stream().mapToInt(List::size).sum());
        
        return specification;
    }
    
    
    public List<CompletionItem> generateCompletions(String partial) {
        List<CompletionItem> completions = new ArrayList<>();
        
        if (partial == null || partial.isEmpty()) {
            
            SECURITY_COMMANDS.keySet().stream()
                .sorted()
                .limit(10)
                .forEach(category -> {
                    completions.add(new CompletionItem(
                        category,
                        "Security command category: " + category
                    ));
                });
        } else {
            
            String lowerPartial = partial.toLowerCase();
            
            
            if (SECURITY_COMMANDS.containsKey(lowerPartial)) {
                SECURITY_COMMANDS.get(lowerPartial).forEach(cmd -> {
                    completions.add(createCompletion(cmd));
                });
            }
            
            
            SECURITY_COMMANDS.entrySet().stream()
                .filter(entry -> entry.getKey().startsWith(lowerPartial))
                .flatMap(entry -> entry.getValue().stream())
                .forEach(cmd -> {
                    completions.add(createCompletion(cmd));
                });
            
            
            SECURITY_COMMANDS.values().stream()
                .flatMap(List::stream)
                .filter(cmd -> cmd.command.toLowerCase().contains(lowerPartial))
                .sorted(Comparator.comparing(cmd -> cmd.command))
                .limit(20)
                .forEach(cmd -> {
                    completions.add(createCompletion(cmd));
                });
        }
        
        return completions;
    }
    
    
    private CompletionItem createCompletion(CommandInfo cmd) {
        return new CompletionItem(
            cmd.command,
            String.format("%s (Example: %s)", cmd.description, cmd.example)
        );
    }
    
    
    private static class CommandInfo {
        final String command;
        final String description;
        final String example;
        
        CommandInfo(String command, String description, String example) {
            this.command = command;
            this.description = description;
            this.example = example;
        }
    }
    
    
    public static class CompletionItem {
        private final String value;
        private final String description;
        
        public CompletionItem(String value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public String getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CompletionItem that = (CompletionItem) o;
            return Objects.equals(value, that.value);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(value);
        }
    }
}