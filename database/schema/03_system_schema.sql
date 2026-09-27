-- ============================================================
-- ASKQ 03: askq_system schema (ASKQ's own application data).
--
-- Structures only. Authentication, RBAC and CAIR logic arrive in later phases.
--
-- user_id columns refer to askq_university.users.user_id. They are logical
-- references WITHOUT cross-database foreign keys, so the two databases stay
-- independent (either can be rebuilt without the other). role_code is a
-- snapshot of the user's role at the time of the event, for auditability.
--
-- Timestamps: TIMESTAMP(3) (millisecond precision). MySQL stores TIMESTAMP in
-- UTC and converts using the session time_zone, so the backend must connect
-- with time_zone = '+00:00' (documented in database/README.md).
-- The append-only tables (ledger, assessments, findings, audit log, results)
-- have no updated_at; askq_app is granted INSERT/SELECT only on them.
-- ============================================================

USE askq_system;

-- Password hashes and login state (populated from Phase 4).
-- Kept out of askq_university so the SELECT-only query account can never read it.
CREATE TABLE app_user_credentials (
    user_id                INT UNSIGNED      NOT NULL,
    password_hash          VARCHAR(255)      NOT NULL,
    password_changed_at    TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    failed_login_attempts  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until           TIMESTAMP(3)      NULL,
    last_login_at          TIMESTAMP(3)      NULL,
    created_at             TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at             TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='user_id -> askq_university.users.user_id (logical reference)';

CREATE TABLE conversations (
    conversation_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    -- Opaque id exposed to the browser instead of the sequential key.
    public_id         CHAR(36)        NOT NULL,
    user_id           INT UNSIGNED    NOT NULL,
    role_code         VARCHAR(20)     NOT NULL,
    title             VARCHAR(200)    NULL,
    status            VARCHAR(8)      NOT NULL DEFAULT 'ACTIVE',
    started_at        TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_activity_at  TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    created_at        TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at        TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (conversation_id),
    UNIQUE KEY uq_conversations_public_id (public_id),
    CONSTRAINT ck_conversations_role     CHECK (role_code IN ('ADMIN', 'HOD', 'TEACHER', 'STUDENT')),
    CONSTRAINT ck_conversations_status   CHECK (status IN ('ACTIVE', 'ARCHIVED')),
    CONSTRAINT ck_conversations_activity CHECK (last_activity_at >= started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One user question within a conversation (the context used for follow-ups).
CREATE TABLE conversation_turns (
    turn_id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    conversation_id  BIGINT UNSIGNED NOT NULL,
    turn_no          INT UNSIGNED    NOT NULL,
    question         TEXT            NOT NULL,
    answer_summary   TEXT            NULL,
    created_at       TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (turn_id),
    UNIQUE KEY uq_turns_conversation_no (conversation_id, turn_no),
    -- Target of query_history's composite FK (a query's turn must belong to
    -- the query's conversation).
    UNIQUE KEY uq_turns_id_conversation (turn_id, conversation_id),
    CONSTRAINT fk_turns_conversation FOREIGN KEY (conversation_id)
        REFERENCES conversations (conversation_id),
    CONSTRAINT ck_turns_no CHECK (turn_no >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One row per question that entered the pipeline, written ONCE when the
-- pipeline finishes (askq_app may not UPDATE it). Records what the LLM proposed,
-- each gate's outcome, and what (if anything) ran. Result rows are never stored.
--
-- Reconstruction chain:
--   conversations -> conversation_turns -> query_history (question, SQL,
--   gate outcomes, execution result) -> cair_assessments -> cair_audit_findings,
--   and cair_ledger_entries (knowledge gained) -> security_audit_log.
--
-- The question text is stored exactly once: in conversation_turns.question for
-- chat queries (turn_id set, question_text NULL), or in question_text for
-- queries with no turn, such as evaluation runs (ck_qh_question_source).
-- resolved_question is the self-contained question actually given to the
-- LLM after conversation context was applied; CAIR's context-carryover audit
-- compares it with the raw question. Questions can contain personal data:
-- see the retention note in database/README.md.
--
-- Pipeline gates, in order: validation -> authorization -> CAIR -> execution.
-- A gate's column is NULL when the pipeline never reached it
-- (ck_qh_stage_order). final_status is the single summary:
--   EXECUTED    ran; CAIR ALLOW
--   RESTRICTED  ran in a restricted form; CAIR RESTRICT (executed_sql is the
--               restricted SQL, e.g. coarsened or with small groups suppressed)
--   BLOCKED     not run; CAIR BLOCK
--   DENIED      not run; RBAC authorization DENIED
--   REJECTED    not run; SQL safety validation REJECTED the generated SQL
--   FAILED      a system error at failure_stage (generation, validation,
--               authorization, CAIR or execution); error_code says what
-- ck_qh_final_status ties each value to the gate columns it implies.
CREATE TABLE query_history (
    query_id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id               INT UNSIGNED    NOT NULL,
    role_code             VARCHAR(20)     NOT NULL,
    conversation_id       BIGINT UNSIGNED NULL,
    turn_id               BIGINT UNSIGNED NULL,
    question_text         TEXT            NULL,
    resolved_question     TEXT            NULL,
    generated_sql         MEDIUMTEXT      NULL,
    validation_status     VARCHAR(8)      NULL,
    authorization_status  VARCHAR(9)      NULL,
    cair_decision         VARCHAR(8)      NULL,
    risk_score            DECIMAL(5,4)    NULL,
    executed_sql          MEDIUMTEXT      NULL,
    final_status          VARCHAR(10)     NOT NULL,
    failure_stage         VARCHAR(13)     NULL,
    error_code            VARCHAR(50)     NULL,
    result_row_count      INT UNSIGNED    NULL,
    execution_ms          INT UNSIGNED    NULL,
    created_at            TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (query_id),
    -- Target of cair_ledger_entries' composite FK (ledger user = query user).
    UNIQUE KEY uq_query_history_id_user (query_id, user_id),
    CONSTRAINT fk_query_history_conversation FOREIGN KEY (conversation_id)
        REFERENCES conversations (conversation_id),
    -- A turn must belong to the query's conversation. Only enforced when
    -- turn_id is set; ck_qh_turn_needs_conversation makes conversation_id
    -- non-NULL in that case.
    CONSTRAINT fk_query_history_turn FOREIGN KEY (turn_id, conversation_id)
        REFERENCES conversation_turns (turn_id, conversation_id),
    CONSTRAINT ck_qh_role    CHECK (role_code IN ('ADMIN', 'HOD', 'TEACHER', 'STUDENT')),
    CONSTRAINT ck_qh_turn_needs_conversation CHECK (turn_id IS NULL OR conversation_id IS NOT NULL),
    CONSTRAINT ck_qh_question_source CHECK ((turn_id IS NULL) <> (question_text IS NULL)),
    CONSTRAINT ck_qh_validation CHECK (validation_status IS NULL
                                       OR validation_status IN ('PASSED', 'REJECTED')),
    CONSTRAINT ck_qh_authz      CHECK (authorization_status IS NULL
                                       OR authorization_status IN ('ALLOWED', 'REWRITTEN', 'DENIED')),
    CONSTRAINT ck_qh_cair       CHECK (cair_decision IS NULL
                                       OR cair_decision IN ('ALLOW', 'RESTRICT', 'BLOCK')),
    CONSTRAINT ck_qh_risk       CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 1),
    CONSTRAINT ck_qh_risk_with_decision CHECK ((risk_score IS NULL) = (cair_decision IS NULL)),
    CONSTRAINT ck_qh_failure_stage CHECK (failure_stage IS NULL OR failure_stage IN
        ('GENERATION', 'VALIDATION', 'AUTHORIZATION', 'CAIR', 'EXECUTION')),
    -- A later gate only has an outcome if every earlier gate let the query through.
    -- NULL-safe on purpose: a CHECK that evaluates to NULL counts as satisfied,
    -- so every comparison on a nullable column goes through COALESCE.
    CONSTRAINT ck_qh_stage_order CHECK (
            (authorization_status IS NULL OR COALESCE(validation_status, '') = 'PASSED')
        AND (cair_decision IS NULL
             OR COALESCE(authorization_status, '') IN ('ALLOWED', 'REWRITTEN'))
        AND (executed_sql IS NULL OR COALESCE(cair_decision, '') IN ('ALLOW', 'RESTRICT'))
        AND (validation_status IS NULL OR generated_sql IS NOT NULL)),
    CONSTRAINT ck_qh_final_status CHECK (
           (final_status = 'EXECUTED'   AND COALESCE(cair_decision, '') = 'ALLOW'
                AND executed_sql IS NOT NULL AND result_row_count IS NOT NULL
                AND failure_stage IS NULL AND error_code IS NULL)
        OR (final_status = 'RESTRICTED' AND COALESCE(cair_decision, '') = 'RESTRICT'
                AND executed_sql IS NOT NULL AND result_row_count IS NOT NULL
                AND failure_stage IS NULL AND error_code IS NULL)
        OR (final_status = 'BLOCKED'    AND COALESCE(cair_decision, '') = 'BLOCK'
                AND executed_sql IS NULL AND result_row_count IS NULL AND failure_stage IS NULL)
        OR (final_status = 'DENIED'     AND COALESCE(authorization_status, '') = 'DENIED'
                AND executed_sql IS NULL AND result_row_count IS NULL AND failure_stage IS NULL)
        OR (final_status = 'REJECTED'   AND COALESCE(validation_status, '') = 'REJECTED'
                AND executed_sql IS NULL AND result_row_count IS NULL AND failure_stage IS NULL)
        OR (final_status = 'FAILED'     AND failure_stage IS NOT NULL AND error_code IS NOT NULL
                AND result_row_count IS NULL
                AND (COALESCE(failure_stage, '') <> 'EXECUTION' OR executed_sql IS NOT NULL)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- CAIR knowledge ledger: what each user has learned from executed queries
-- (append-only). The conversation is reached through query_history. user_id
-- is repeated because CAIR reads a user's ledger on every query; the composite
-- FK guarantees it equals the query's user.
CREATE TABLE cair_ledger_entries (
    entry_id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    query_id                BIGINT UNSIGNED NOT NULL,
    user_id                 INT UNSIGNED    NOT NULL,
    -- Structured descriptor of the executed query (tables, columns,
    -- predicates, aggregates, groupings), derived from the parsed SQL.
    descriptor              JSON            NOT NULL,
    -- SHA-256 (hex) identifying the population (row set) the query ranged over.
    population_fingerprint  CHAR(64)        NOT NULL,
    result_cardinality      INT UNSIGNED    NULL,
    created_at              TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (entry_id),
    CONSTRAINT fk_ledger_query FOREIGN KEY (query_id, user_id)
        REFERENCES query_history (query_id, user_id),
    CONSTRAINT ck_ledger_fingerprint CHECK (REGEXP_LIKE(population_fingerprint, '^[0-9a-f]{64}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Why CAIR decided what it did for one query (append-only). The decision and
-- risk score themselves are recorded once, in query_history.
CREATE TABLE cair_assessments (
    assessment_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    query_id        BIGINT UNSIGNED NOT NULL,
    policy_version  VARCHAR(20)     NOT NULL,
    reasons         JSON            NOT NULL,
    created_at      TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (assessment_id),
    UNIQUE KEY uq_assessments_query (query_id),
    CONSTRAINT fk_assessments_query FOREIGN KEY (query_id) REFERENCES query_history (query_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Per-audit detail behind an assessment: one row per CAIR audit (append-only).
CREATE TABLE cair_audit_findings (
    finding_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    assessment_id  BIGINT UNSIGNED NOT NULL,
    audit_type     VARCHAR(20)     NOT NULL,
    score          DECIMAL(5,4)    NOT NULL,
    triggered      TINYINT(1)      NOT NULL,
    explanation    VARCHAR(1000)   NOT NULL,
    evidence       JSON            NULL,
    created_at     TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (finding_id),
    UNIQUE KEY uq_findings_assessment_audit (assessment_id, audit_type),
    CONSTRAINT fk_findings_assessment FOREIGN KEY (assessment_id)
        REFERENCES cair_assessments (assessment_id),
    CONSTRAINT ck_findings_audit_type CHECK (audit_type IN
        ('DIFFERENCING', 'NARROWING', 'ARITHMETIC_RECOVERY',
         'CROSS_VIEW_LINKING', 'REFUSAL_SIDE_CHANNEL', 'CONTEXT_CARRYOVER')),
    CONSTRAINT ck_findings_score     CHECK (score BETWEEN 0 AND 1),
    CONSTRAINT ck_findings_triggered CHECK (triggered IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Security-relevant events: logins, denials, validation rejections, CAIR
-- blocks, configuration changes (append-only).
CREATE TABLE security_audit_log (
    audit_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    occurred_at  TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    user_id      INT UNSIGNED    NULL,
    event_type   VARCHAR(50)     NOT NULL,
    severity     VARCHAR(8)      NOT NULL,
    query_id     BIGINT UNSIGNED NULL,
    client_ip    VARCHAR(45)     NULL,
    details      JSON            NULL,
    PRIMARY KEY (audit_id),
    CONSTRAINT fk_audit_query FOREIGN KEY (query_id) REFERENCES query_history (query_id),
    CONSTRAINT ck_audit_event_type CHECK (REGEXP_LIKE(event_type, '^[A-Z][A-Z0-9_]*$', 'c')),
    CONSTRAINT ck_audit_severity   CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One evaluation run (e.g. the attack suite with CAIR on vs. the baseline).
CREATE TABLE evaluation_runs (
    run_id        INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    run_name      VARCHAR(100)  NOT NULL,
    mode          VARCHAR(8)    NOT NULL,
    config        JSON          NOT NULL,
    dataset_seed  INT UNSIGNED  NULL,
    status        VARCHAR(9)    NOT NULL DEFAULT 'RUNNING',
    started_at    TIMESTAMP(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    finished_at   TIMESTAMP(3)  NULL,
    notes         TEXT          NULL,
    created_at    TIMESTAMP(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    TIMESTAMP(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (run_id),
    CONSTRAINT ck_eval_runs_mode     CHECK (mode IN ('BASELINE', 'CAIR')),
    CONSTRAINT ck_eval_runs_status   CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    CONSTRAINT ck_eval_runs_finished CHECK (finished_at IS NULL OR finished_at >= started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One step of one scenario within a run (append-only).
CREATE TABLE evaluation_results (
    result_id          BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    run_id             INT UNSIGNED      NOT NULL,
    scenario_code      VARCHAR(50)       NOT NULL,
    step_no            SMALLINT UNSIGNED NOT NULL,
    -- NULL for benign (non-attack) scenarios.
    attack_class       VARCHAR(20)       NULL,
    question           TEXT              NOT NULL,
    expected_decision  VARCHAR(8)        NOT NULL,
    actual_decision    VARCHAR(8)        NULL,
    risk_score         DECIMAL(5,4)      NULL,
    latency_ms         INT UNSIGNED      NULL,
    query_id           BIGINT UNSIGNED   NULL,
    created_at         TIMESTAMP(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (result_id),
    UNIQUE KEY uq_eval_results_step (run_id, scenario_code, step_no),
    CONSTRAINT fk_eval_results_run   FOREIGN KEY (run_id)   REFERENCES evaluation_runs (run_id),
    CONSTRAINT fk_eval_results_query FOREIGN KEY (query_id) REFERENCES query_history (query_id),
    CONSTRAINT ck_eval_results_step   CHECK (step_no >= 1),
    CONSTRAINT ck_eval_results_attack CHECK (attack_class IS NULL OR attack_class IN
        ('DIFFERENCING', 'NARROWING', 'ARITHMETIC_RECOVERY',
         'CROSS_VIEW_LINKING', 'REFUSAL_SIDE_CHANNEL', 'CONTEXT_CARRYOVER')),
    CONSTRAINT ck_eval_results_expected CHECK (expected_decision IN ('ALLOW', 'RESTRICT', 'BLOCK')),
    CONSTRAINT ck_eval_results_actual   CHECK (actual_decision IS NULL
                                               OR actual_decision IN ('ALLOW', 'RESTRICT', 'BLOCK')),
    CONSTRAINT ck_eval_results_risk     CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
