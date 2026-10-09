-- Anonymous daily counts the screens report (works 15 and 18 of docs/showcase/화면설계서-v2-구현계획.md, ADR-35):
-- how many answered each understanding question right or wrong, and how many reached each act. A row holds a day, a
-- metric, an item, a value and a count, and nothing that names or links a visitor. A visitor is counted once per
-- question and once per act (the visitor's journey remembers it); the rows are deleted after the visitor period.
CREATE TABLE anonymous_tally (
    day      DATE          NOT NULL,
    metric   VARCHAR(24)   NOT NULL,
    item     VARCHAR(24)   NOT NULL,
    value    VARCHAR(24)   NOT NULL,
    count    BIGINT        NOT NULL,
    PRIMARY KEY (day, metric, item, value),
    CONSTRAINT anonymous_tally_metric_chk CHECK (metric IN ('QUIZ', 'ACT_REACHED'))
);
