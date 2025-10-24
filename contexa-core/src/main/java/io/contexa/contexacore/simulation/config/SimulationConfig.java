package io.contexa.contexacore.simulation.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 시뮬레이션 설정 클래스
 * application-simulation.yml의 설정을 매핑
 */
@Configuration
@ConfigurationProperties(prefix = "simulation")
@EnableConfigurationProperties
@PropertySource(value = "classpath:application-simulation.yml", factory = YamlPropertySourceFactory.class)
public class SimulationConfig {

    private AttackIps attackIps = new AttackIps();
    private UserAgents userAgents = new UserAgents();
    private AttackPatterns attackPatterns = new AttackPatterns();
    private Map<String, String> locations;
    private Map<String, Integer> distances;
    private Timezones timezones = new Timezones();
    private RiskScores riskScores = new RiskScores();
    private TestAccounts testAccounts = new TestAccounts();

    // Getters and Setters
    public AttackIps getAttackIps() {
        return attackIps;
    }

    public void setAttackIps(AttackIps attackIps) {
        this.attackIps = attackIps;
    }

    public UserAgents getUserAgents() {
        return userAgents;
    }

    public void setUserAgents(UserAgents userAgents) {
        this.userAgents = userAgents;
    }

    public AttackPatterns getAttackPatterns() {
        return attackPatterns;
    }

    public void setAttackPatterns(AttackPatterns attackPatterns) {
        this.attackPatterns = attackPatterns;
    }

    public Map<String, String> getLocations() {
        return locations;
    }

    public void setLocations(Map<String, String> locations) {
        this.locations = locations;
    }

    public Map<String, Integer> getDistances() {
        return distances;
    }

    public void setDistances(Map<String, Integer> distances) {
        this.distances = distances;
    }

    public Timezones getTimezones() {
        return timezones;
    }

    public void setTimezones(Timezones timezones) {
        this.timezones = timezones;
    }

    public RiskScores getRiskScores() {
        return riskScores;
    }

    public void setRiskScores(RiskScores riskScores) {
        this.riskScores = riskScores;
    }

    public TestAccounts getTestAccounts() {
        return testAccounts;
    }

    public void setTestAccounts(TestAccounts testAccounts) {
        this.testAccounts = testAccounts;
    }

    // Inner Classes
    public static class AttackIps {
        private SessionHijacking sessionHijacking = new SessionHijacking();
        private ImpossibleTravel impossibleTravel = new ImpossibleTravel();
        private List<String> suspicious;
        private Normal normal = new Normal();

        public static class SessionHijacking {
            private String original;
            private String hijacked;

            public String getOriginal() {
                return original;
            }

            public void setOriginal(String original) {
                this.original = original;
            }

            public String getHijacked() {
                return hijacked;
            }

            public void setHijacked(String hijacked) {
                this.hijacked = hijacked;
            }
        }

        public static class ImpossibleTravel {
            private String korea;
            private String usa;
            private String russia;
            private String china;

            public String getKorea() {
                return korea;
            }

            public void setKorea(String korea) {
                this.korea = korea;
            }

            public String getUsa() {
                return usa;
            }

            public void setUsa(String usa) {
                this.usa = usa;
            }

            public String getRussia() {
                return russia;
            }

            public void setRussia(String russia) {
                this.russia = russia;
            }

            public String getChina() {
                return china;
            }

            public void setChina(String china) {
                this.china = china;
            }
        }

        public static class Normal {
            private String subnet;
            private List<String> trusted;

            public String getSubnet() {
                return subnet;
            }

            public void setSubnet(String subnet) {
                this.subnet = subnet;
            }

            public List<String> getTrusted() {
                return trusted;
            }

            public void setTrusted(List<String> trusted) {
                this.trusted = trusted;
            }
        }

        public SessionHijacking getSessionHijacking() {
            return sessionHijacking;
        }

        public void setSessionHijacking(SessionHijacking sessionHijacking) {
            this.sessionHijacking = sessionHijacking;
        }

        public ImpossibleTravel getImpossibleTravel() {
            return impossibleTravel;
        }

        public void setImpossibleTravel(ImpossibleTravel impossibleTravel) {
            this.impossibleTravel = impossibleTravel;
        }

        public List<String> getSuspicious() {
            return suspicious;
        }

        public void setSuspicious(List<String> suspicious) {
            this.suspicious = suspicious;
        }

        public Normal getNormal() {
            return normal;
        }

        public void setNormal(Normal normal) {
            this.normal = normal;
        }
    }

    public static class UserAgents {
        private List<String> normal;
        private List<String> suspicious;

        public List<String> getNormal() {
            return normal;
        }

        public void setNormal(List<String> normal) {
            this.normal = normal;
        }

        public List<String> getSuspicious() {
            return suspicious;
        }

        public void setSuspicious(List<String> suspicious) {
            this.suspicious = suspicious;
        }
    }

    public static class AttackPatterns {
        private CredentialStuffing credentialStuffing = new CredentialStuffing();
        private PrivilegeEscalation privilegeEscalation = new PrivilegeEscalation();
        private ApiAbuse apiAbuse = new ApiAbuse();
        private MfaBypass mfaBypass = new MfaBypass();

        public static class CredentialStuffing {
            private List<Credential> attempts;

            public static class Credential {
                private String username;
                private String password;

                public String getUsername() {
                    return username;
                }

                public void setUsername(String username) {
                    this.username = username;
                }

                public String getPassword() {
                    return password;
                }

                public void setPassword(String password) {
                    this.password = password;
                }
            }

            public List<Credential> getAttempts() {
                return attempts;
            }

            public void setAttempts(List<Credential> attempts) {
                this.attempts = attempts;
            }
        }

        public static class PrivilegeEscalation {
            private Endpoints endpoints = new Endpoints();

            public static class Endpoints {
                private List<String> admin;
                private List<String> finance;
                private List<String> infrastructure;
                private List<String> development;

                public List<String> getAdmin() {
                    return admin;
                }

                public void setAdmin(List<String> admin) {
                    this.admin = admin;
                }

                public List<String> getFinance() {
                    return finance;
                }

                public void setFinance(List<String> finance) {
                    this.finance = finance;
                }

                public List<String> getInfrastructure() {
                    return infrastructure;
                }

                public void setInfrastructure(List<String> infrastructure) {
                    this.infrastructure = infrastructure;
                }

                public List<String> getDevelopment() {
                    return development;
                }

                public void setDevelopment(List<String> development) {
                    this.development = development;
                }
            }

            public Endpoints getEndpoints() {
                return endpoints;
            }

            public void setEndpoints(Endpoints endpoints) {
                this.endpoints = endpoints;
            }
        }

        public static class ApiAbuse {
            private RateLimits rateLimits = new RateLimits();
            private int timeWindow;

            public static class RateLimits {
                private int normal;
                private int elevated;
                private int abusive;

                public int getNormal() {
                    return normal;
                }

                public void setNormal(int normal) {
                    this.normal = normal;
                }

                public int getElevated() {
                    return elevated;
                }

                public void setElevated(int elevated) {
                    this.elevated = elevated;
                }

                public int getAbusive() {
                    return abusive;
                }

                public void setAbusive(int abusive) {
                    this.abusive = abusive;
                }
            }

            public RateLimits getRateLimits() {
                return rateLimits;
            }

            public void setRateLimits(RateLimits rateLimits) {
                this.rateLimits = rateLimits;
            }

            public int getTimeWindow() {
                return timeWindow;
            }

            public void setTimeWindow(int timeWindow) {
                this.timeWindow = timeWindow;
            }
        }

        public static class MfaBypass {
            private List<String> methods;

            public List<String> getMethods() {
                return methods;
            }

            public void setMethods(List<String> methods) {
                this.methods = methods;
            }
        }

        public CredentialStuffing getCredentialStuffing() {
            return credentialStuffing;
        }

        public void setCredentialStuffing(CredentialStuffing credentialStuffing) {
            this.credentialStuffing = credentialStuffing;
        }

        public PrivilegeEscalation getPrivilegeEscalation() {
            return privilegeEscalation;
        }

        public void setPrivilegeEscalation(PrivilegeEscalation privilegeEscalation) {
            this.privilegeEscalation = privilegeEscalation;
        }

        public ApiAbuse getApiAbuse() {
            return apiAbuse;
        }

        public void setApiAbuse(ApiAbuse apiAbuse) {
            this.apiAbuse = apiAbuse;
        }

        public MfaBypass getMfaBypass() {
            return mfaBypass;
        }

        public void setMfaBypass(MfaBypass mfaBypass) {
            this.mfaBypass = mfaBypass;
        }
    }

    public static class Timezones {
        private NormalHours normalHours = new NormalHours();
        private SuspiciousHours suspiciousHours = new SuspiciousHours();

        public static class NormalHours {
            private int start;
            private int end;

            public int getStart() {
                return start;
            }

            public void setStart(int start) {
                this.start = start;
            }

            public int getEnd() {
                return end;
            }

            public void setEnd(int end) {
                this.end = end;
            }
        }

        public static class SuspiciousHours {
            private List<Integer> earlyMorning;
            private List<Integer> lateNight;

            public List<Integer> getEarlyMorning() {
                return earlyMorning;
            }

            public void setEarlyMorning(List<Integer> earlyMorning) {
                this.earlyMorning = earlyMorning;
            }

            public List<Integer> getLateNight() {
                return lateNight;
            }

            public void setLateNight(List<Integer> lateNight) {
                this.lateNight = lateNight;
            }
        }

        public NormalHours getNormalHours() {
            return normalHours;
        }

        public void setNormalHours(NormalHours normalHours) {
            this.normalHours = normalHours;
        }

        public SuspiciousHours getSuspiciousHours() {
            return suspiciousHours;
        }

        public void setSuspiciousHours(SuspiciousHours suspiciousHours) {
            this.suspiciousHours = suspiciousHours;
        }
    }

    public static class RiskScores {
        private double ipChange;
        private double deviceChange;
        private double locationChange;
        private double impossibleTravel;
        private double suspiciousAgent;
        private double offHours;
        private double repeatedAttempts;

        public double getIpChange() {
            return ipChange;
        }

        public void setIpChange(double ipChange) {
            this.ipChange = ipChange;
        }

        public double getDeviceChange() {
            return deviceChange;
        }

        public void setDeviceChange(double deviceChange) {
            this.deviceChange = deviceChange;
        }

        public double getLocationChange() {
            return locationChange;
        }

        public void setLocationChange(double locationChange) {
            this.locationChange = locationChange;
        }

        public double getImpossibleTravel() {
            return impossibleTravel;
        }

        public void setImpossibleTravel(double impossibleTravel) {
            this.impossibleTravel = impossibleTravel;
        }

        public double getSuspiciousAgent() {
            return suspiciousAgent;
        }

        public void setSuspiciousAgent(double suspiciousAgent) {
            this.suspiciousAgent = suspiciousAgent;
        }

        public double getOffHours() {
            return offHours;
        }

        public void setOffHours(double offHours) {
            this.offHours = offHours;
        }

        public double getRepeatedAttempts() {
            return repeatedAttempts;
        }

        public void setRepeatedAttempts(double repeatedAttempts) {
            this.repeatedAttempts = repeatedAttempts;
        }
    }

    public static class TestAccounts {
        private boolean enabled;
        private List<TestAccount> accounts;

        public static class TestAccount {
            private String username;
            private double threatScore;
            private String role;

            public String getUsername() {
                return username;
            }

            public void setUsername(String username) {
                this.username = username;
            }

            public double getThreatScore() {
                return threatScore;
            }

            public void setThreatScore(double threatScore) {
                this.threatScore = threatScore;
            }

            public String getRole() {
                return role;
            }

            public void setRole(String role) {
                this.role = role;
            }
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<TestAccount> getAccounts() {
            return accounts;
        }

        public void setAccounts(List<TestAccount> accounts) {
            this.accounts = accounts;
        }
    }
}