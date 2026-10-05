-- Virtual company foundation. The organization generator fills these tables from a fixed seed.
CREATE TABLE role (
    role_key         VARCHAR(32)  PRIMARY KEY,
    display_name_en  VARCHAR(64)  NOT NULL,
    display_name_ko  VARCHAR(64)  NOT NULL
);

CREATE TABLE employee (
    employee_key  VARCHAR(64)  PRIMARY KEY,
    role_key      VARCHAR(32)  NOT NULL REFERENCES role (role_key),
    display_name  VARCHAR(128) NOT NULL,
    department    VARCHAR(64)  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX employee_role_idx ON employee (role_key);
