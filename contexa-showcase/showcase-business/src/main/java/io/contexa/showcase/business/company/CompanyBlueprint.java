package io.contexa.showcase.business.company;

import java.util.List;

/**
 * Fixed shape of the virtual company (docs/showcase/ADR.md ADR-19): roles and head counts from the v5 deck,
 * the design projects of a manufacturer, the two protagonists and their usual devices and networks.
 * Changing anything here changes the generated data; bump {@link CompanyGenerator#VERSION} with it.
 */
public final class CompanyBlueprint {

    public static final String ROLE_ENGINEER = "ENGINEER";
    public static final String ROLE_SALES = "SALES";
    public static final String ROLE_PM = "PM";
    public static final String ROLE_PARTNER = "PARTNER";
    public static final String ROLE_FINANCE = "FINANCE";
    public static final String ROLE_ADMIN = "ADMIN";

    /** Protagonist of the representative scene: administrator A (deck p.9, p.10). */
    public static final String ADMIN_A = "adm-a";

    /** Protagonist of the control and recovery scene: design engineer K (deck p.12). */
    public static final String ENGINEER_K = "eng-k";

    /** Internal project of the IT administration team that administrator A works on. */
    public static final String PLM_OPERATIONS = "PLM-OPS";

    /** Design project of engineer K. */
    public static final String K_PROJECT = "HX-310";

    /** Large restricted project administrator A is not assigned to (the bulk export target of scene A3). */
    public static final String A3_TARGET = "GB-500";

    public static final String EMAIL_DOMAIN = "showcase.invalid";

    /** Usual device of administrator A. */
    public static final String ADMIN_A_DEVICE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

    /** Usual device of engineer K, a design workstation. */
    public static final String ENGINEER_K_DEVICE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0";

    /** Device that no employee has used before; the "new device" condition (deck p.13). */
    public static final String NEW_DEVICE = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 "
            + "(KHTML, like Gecko) Version/18.0 Safari/605.1.15";

    record RoleSpec(String roleKey, String keyPrefix, String displayNameEn, String displayNameKo, int headCount) {
    }

    record ProjectSpec(String projectKey, String displayName, String program, String sensitivity, int documents) {
    }

    record ProgramSpec(String program, String officeNetwork, List<String> parts) {
    }

    /** Head counts are the deck's initial proposal (p.26). */
    static final List<RoleSpec> ROLES = List.of(
            new RoleSpec(ROLE_ENGINEER, "eng", "Design engineer", "설계 엔지니어", 60),
            new RoleSpec(ROLE_SALES, "sal", "Sales", "영업", 20),
            new RoleSpec(ROLE_PM, "pm", "Project manager", "PM", 12),
            new RoleSpec(ROLE_PARTNER, "prt", "Partner engineer", "협력사", 12),
            new RoleSpec(ROLE_FINANCE, "fin", "Finance", "재무", 10),
            new RoleSpec(ROLE_ADMIN, "adm", "Administrator", "관리자", 6));

    static final List<ProgramSpec> PROGRAMS = List.of(
            new ProgramSpec("HX", "10.40.21.0/24", List.of("Tube sheet", "Baffle plate", "Shell flange",
                    "Nozzle reinforcement", "Channel cover", "Gasket seat", "Tie rod", "Expansion joint")),
            new ProgramSpec("CP", "10.40.22.0/24", List.of("Impeller", "Diffuser vane", "Rotor shaft",
                    "Volute casing", "Thrust bearing", "Labyrinth seal", "Inlet guide vane", "Coupling hub")),
            new ProgramSpec("PM", "10.40.23.0/24", List.of("Pump casing", "Mechanical seal", "Wear ring",
                    "Bearing housing", "Suction cover", "Shaft sleeve", "Base frame", "Motor adapter")),
            new ProgramSpec("VL", "10.40.24.0/24", List.of("Valve body", "Trim cage", "Plug stem",
                    "Bonnet", "Actuator yoke", "Seat ring", "Packing box", "Positioner bracket")),
            new ProgramSpec("GB", "10.40.25.0/24", List.of("Planet carrier", "Sun gear", "Ring gear",
                    "Output shaft", "Housing half", "Oil pump", "Bearing cap", "Torque arm")),
            new ProgramSpec("IT", "10.40.12.0/24", List.of("PLM workflow", "Access review", "Backup policy",
                    "Release checklist", "Vault index", "License inventory", "Change calendar", "Runbook")));

    /** The design projects; GB-500 holds more than 5,000 documents for the largest export condition. */
    static final List<ProjectSpec> PROJECTS = List.of(
            new ProjectSpec(PLM_OPERATIONS, "PLM operations", "IT", "INTERNAL", 420),
            new ProjectSpec("HX-200", "HX-200 plate heat exchanger", "HX", "CONFIDENTIAL", 900),
            new ProjectSpec(K_PROJECT, "HX-310 shell-and-tube heat exchanger", "HX", "CONFIDENTIAL", 1100),
            new ProjectSpec("HX-450", "HX-450 condenser", "HX", "CONFIDENTIAL", 760),
            new ProjectSpec("CP-120", "CP-120 scroll compressor", "CP", "CONFIDENTIAL", 680),
            new ProjectSpec("CP-220", "CP-220 screw compressor", "CP", "CONFIDENTIAL", 1240),
            new ProjectSpec("CP-330", "CP-330 centrifugal compressor", "CP", "RESTRICTED", 2600),
            new ProjectSpec("PM-050", "PM-050 circulation pump", "PM", "INTERNAL", 520),
            new ProjectSpec("PM-075", "PM-075 booster pump", "PM", "CONFIDENTIAL", 610),
            new ProjectSpec("VL-010", "VL-010 control valve", "VL", "INTERNAL", 450),
            new ProjectSpec("GB-400", "GB-400 gearbox", "GB", "CONFIDENTIAL", 980),
            new ProjectSpec(A3_TARGET, "GB-500 planetary gearbox", "GB", "RESTRICTED", 6400));

    static final String ADMIN_NETWORK = "10.40.12.0/24";
    static final String PM_NETWORK = "10.40.51.0/24";
    static final String SALES_NETWORK = "10.40.31.0/24";
    static final String FINANCE_NETWORK = "10.40.41.0/24";
    static final String PARTNER_NETWORK = "10.40.61.0/24";

    static final List<String> REGIONS = List.of("KR", "JP", "DE", "US", "FR", "IN");

    static final List<String> DEVICE_AGENTS = List.of(
            ADMIN_A_DEVICE,
            ENGINEER_K_DEVICE,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36");

    static final List<String> DOCUMENT_SENTENCES = List.of(
            "Dimensions follow the released interface control document.",
            "Tolerances were tightened after the last design review.",
            "Material callouts reference the approved supplier list.",
            "Weld symbols follow the company drafting standard.",
            "Surface finish requirements apply to all machined faces.",
            "This revision closes the open action items from the test campaign.",
            "Critical-to-quality characteristics are marked on sheet one.",
            "Changes are tracked in the engineering change notice log.");

    private CompanyBlueprint() {
    }
}
