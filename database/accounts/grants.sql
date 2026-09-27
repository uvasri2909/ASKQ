-- ============================================================
-- ASKQ: least-privilege grants for the two application accounts.
--
-- Contains NO passwords. The accounts themselves are created by
-- database\setup_db.ps1 from DB_READER_PASSWORD / DB_APP_PASSWORD in the
-- git-ignored .env, and this file is then run to (re)apply privileges.
-- Idempotent: all privileges are revoked first, so re-running never leaves
-- a stale grant behind.
--
-- Host: both accounts exist ONLY as '<name>'@'127.0.0.1'. The backend and the
-- verification script connect to 127.0.0.1 over TCP (DB_HOST in .env), which
-- matches an IP-literal account host whether or not the server resolves
-- host names, so no skip-name-resolve change is needed.
--
-- Only table-level SELECT/INSERT/UPDATE grants appear below. Nothing here
-- grants: database-wide or global (*.*) privileges, DELETE, DDL (CREATE,
-- ALTER, DROP, INDEX, CREATE VIEW, TRIGGER), CREATE TEMPORARY TABLES, LOCK
-- TABLES, EXECUTE/CREATE ROUTINE, FILE, PROCESS, SUPER, dynamic admin
-- privileges, or GRANT OPTION.
-- ============================================================

REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'askq_reader'@'127.0.0.1';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'askq_app'@'127.0.0.1';

-- ---------- askq_reader: executes validated, LLM-generated SELECTs ----------
-- SELECT on the organisational tables a question can legitimately need, and
-- the two derived views. Deliberately NOT granted:
--   askq_university.users  login identities (application metadata)
--   askq_university.roles  application metadata, never needed to answer a question
--   askq_system.*          credentials, history, CAIR ledger, audit log
GRANT SELECT ON askq_university.departments          TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.academic_terms       TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.grade_scale          TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.teachers             TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.students             TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.courses              TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.course_offerings     TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.enrollments          TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.grades               TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.class_sessions       TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.attendance_records   TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.fees                 TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.fee_payments         TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.scholarships         TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.student_scholarships TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.v_fee_balances       TO 'askq_reader'@'127.0.0.1';
GRANT SELECT ON askq_university.v_attendance_summary TO 'askq_reader'@'127.0.0.1';

-- ---------- askq_app: the backend's own bookkeeping ----------
-- Read-only lookups needed to authenticate a user and resolve their scope
-- (role; linked teacher/student; which department a HOD heads).
GRANT SELECT ON askq_university.users       TO 'askq_app'@'127.0.0.1';
GRANT SELECT ON askq_university.roles       TO 'askq_app'@'127.0.0.1';
GRANT SELECT ON askq_university.departments TO 'askq_app'@'127.0.0.1';

-- Mutable state: no DELETE anywhere (conversations are archived, not deleted).
GRANT SELECT, INSERT, UPDATE ON askq_system.app_user_credentials TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON askq_system.conversations        TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON askq_system.conversation_turns   TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE ON askq_system.evaluation_runs      TO 'askq_app'@'127.0.0.1';

-- Append-only records: written once, never changed.
GRANT SELECT, INSERT ON askq_system.query_history       TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT ON askq_system.cair_ledger_entries TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT ON askq_system.cair_assessments    TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT ON askq_system.cair_audit_findings TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT ON askq_system.security_audit_log  TO 'askq_app'@'127.0.0.1';
GRANT SELECT, INSERT ON askq_system.evaluation_results  TO 'askq_app'@'127.0.0.1';
