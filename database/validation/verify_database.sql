-- ============================================================
-- ASKQ: post-load verification of both databases (read-only; run as the
-- admin account by database\setup_db.ps1).
--
-- Every check inserts one PASS/FAIL row into a session-scoped temporary
-- table. The final INSERT into verify_gate violates a CHECK constraint
-- (error 3819, all_database_checks_must_pass) when any check failed, so a
-- mysql session running this file exits non-zero. Nothing persistent is
-- created or modified.
--
-- The 'accounts' checks read mysql.* grant tables. They pass trivially when
-- the ASKQ accounts do not exist yet (setup_db.ps1 -SkipAccounts).
-- The exact constraint counts are kept in sync with the DDL by
-- backend/tests/test_database_sql.py.
-- ============================================================

SET time_zone = '+00:00';
USE askq_university;

DROP TEMPORARY TABLE IF EXISTS verify_results;
CREATE TEMPORARY TABLE verify_results (
    check_no    INT AUTO_INCREMENT PRIMARY KEY,
    area        VARCHAR(12),
    check_name  VARCHAR(80),
    expected    VARCHAR(30),
    actual      BIGINT,
    result      CHAR(4)
);

-- ---------- Row counts ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'rows', 'roles', '= 4', n, IF(n = 4, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM roles) q UNION ALL
SELECT 'rows', 'departments', '= 7', n, IF(n = 7, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM departments) q UNION ALL
SELECT 'rows', 'academic_terms', '= 2', n, IF(n = 2, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM academic_terms) q UNION ALL
SELECT 'rows', 'grade_scale', '= 9', n, IF(n = 9, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM grade_scale) q UNION ALL
SELECT 'rows', 'courses', '= 91', n, IF(n = 91, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM courses) q UNION ALL
SELECT 'rows', 'scholarships', '= 6', n, IF(n = 6, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM scholarships) q UNION ALL
SELECT 'rows', 'teachers', '= 40', n, IF(n = 40, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM teachers) q UNION ALL
SELECT 'rows', 'students', '= 1000', n, IF(n = 1000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM students) q UNION ALL
SELECT 'rows', 'users', '= 1041', n, IF(n = 1041, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM users) q UNION ALL
SELECT 'rows', 'course_offerings', '150..250', n, IF(n BETWEEN 150 AND 250, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM course_offerings) q UNION ALL
SELECT 'rows', 'class_sessions', '2000..5000', n, IF(n BETWEEN 2000 AND 5000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM class_sessions) q UNION ALL
SELECT 'rows', 'enrollments', '6000..8000', n, IF(n BETWEEN 6000 AND 8000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM enrollments) q UNION ALL
SELECT 'rows', 'grades', '2000..4000', n, IF(n BETWEEN 2000 AND 4000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM grades) q UNION ALL
SELECT 'rows', 'attendance_records', '90000..150000', n, IF(n BETWEEN 90000 AND 150000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM attendance_records) q UNION ALL
SELECT 'rows', 'fees', '6000..9000', n, IF(n BETWEEN 6000 AND 9000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM fees) q UNION ALL
SELECT 'rows', 'fee_payments', '5000..9000', n, IF(n BETWEEN 5000 AND 9000, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM fee_payments) q UNION ALL
SELECT 'rows', 'student_scholarships', '100..400', n, IF(n BETWEEN 100 AND 400, 'PASS', 'FAIL') FROM (SELECT COUNT(*) n FROM student_scholarships) q;

-- ---------- Structure ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'structure', 'askq_university base tables', '= 17', n, IF(n = 17, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = 'askq_university' AND TABLE_TYPE = 'BASE TABLE') q UNION ALL
SELECT 'structure', 'askq_system base tables', '= 10', n, IF(n = 10, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = 'askq_system' AND TABLE_TYPE = 'BASE TABLE') q UNION ALL
SELECT 'structure', 'SQL SECURITY INVOKER views', '= 2', n, IF(n = 2, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.VIEWS
        WHERE TABLE_SCHEMA = 'askq_university' AND SECURITY_TYPE = 'INVOKER') q UNION ALL
SELECT 'structure', 'views reading the clock (curdate/now)', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.VIEWS
        WHERE TABLE_SCHEMA = 'askq_university'
          AND (LOWER(VIEW_DEFINITION) LIKE '%curdate()%' OR LOWER(VIEW_DEFINITION) LIKE '%now()%'
               OR LOWER(VIEW_DEFINITION) LIKE '%current_timestamp%'
               OR LOWER(VIEW_DEFINITION) LIKE '%sysdate()%')) q UNION ALL
SELECT 'structure', 'tables not InnoDB/utf8mb4', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLES
        WHERE TABLE_SCHEMA IN ('askq_university', 'askq_system') AND TABLE_TYPE = 'BASE TABLE'
          AND (ENGINE <> 'InnoDB' OR TABLE_COLLATION <> 'utf8mb4_0900_ai_ci')) q UNION ALL
SELECT 'structure', 'tables without a primary key', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLES t
        WHERE t.TABLE_SCHEMA IN ('askq_university', 'askq_system') AND t.TABLE_TYPE = 'BASE TABLE'
          AND NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS c
                          WHERE c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
                            AND c.CONSTRAINT_TYPE = 'PRIMARY KEY')) q UNION ALL
SELECT 'structure', 'foreign keys (both databases)', '= 34', n, IF(n = 34, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA IN ('askq_university', 'askq_system') AND CONSTRAINT_TYPE = 'FOREIGN KEY') q UNION ALL
SELECT 'structure', 'unique keys (both databases)', '= 37', n, IF(n = 37, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA IN ('askq_university', 'askq_system') AND CONSTRAINT_TYPE = 'UNIQUE') q UNION ALL
SELECT 'structure', 'enforced check constraints', '= 73', n, IF(n = 73, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM information_schema.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA IN ('askq_university', 'askq_system') AND CONSTRAINT_TYPE = 'CHECK'
          AND ENFORCED = 'YES') q UNION ALL
SELECT 'structure', 'askq_system rows (must start empty)', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT (SELECT COUNT(*) FROM askq_system.app_user_credentials)
             + (SELECT COUNT(*) FROM askq_system.conversations)
             + (SELECT COUNT(*) FROM askq_system.conversation_turns)
             + (SELECT COUNT(*) FROM askq_system.query_history)
             + (SELECT COUNT(*) FROM askq_system.cair_ledger_entries)
             + (SELECT COUNT(*) FROM askq_system.cair_assessments)
             + (SELECT COUNT(*) FROM askq_system.cair_audit_findings)
             + (SELECT COUNT(*) FROM askq_system.security_audit_log)
             + (SELECT COUNT(*) FROM askq_system.evaluation_runs)
             + (SELECT COUNT(*) FROM askq_system.evaluation_results) AS n) q;

-- ---------- Temporal determinism (DATA_AS_OF 2026-09-25, snapshot 18:00:00 UTC) ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'temporal', 'v_fee_balances not judged as of 2026-09-25', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM v_fee_balances WHERE status_as_of <> DATE '2026-09-25') q UNION ALL
SELECT 'temporal', 'seed rows not stamped 2026-09-25 18:00:00 UTC', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT (SELECT COUNT(*) FROM students WHERE created_at <> '2026-09-25 18:00:00' OR updated_at <> '2026-09-25 18:00:00')
             + (SELECT COUNT(*) FROM teachers WHERE created_at <> '2026-09-25 18:00:00')
             + (SELECT COUNT(*) FROM departments WHERE updated_at <> '2026-09-25 18:00:00')
             + (SELECT COUNT(*) FROM enrollments WHERE created_at <> '2026-09-25 18:00:00')
             + (SELECT COUNT(*) FROM grades WHERE created_at <> '2026-09-25 18:00:00')
             + (SELECT COUNT(*) FROM attendance_records WHERE created_at <> '2026-09-25 18:00:00')
             + (SELECT COUNT(*) FROM fee_payments WHERE created_at <> '2026-09-25 18:00:00') AS n) q UNION ALL
SELECT 'temporal', 'payments or sessions after 2026-09-25', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT (SELECT COUNT(*) FROM fee_payments WHERE paid_on > DATE '2026-09-25')
             + (SELECT COUNT(*) FROM class_sessions WHERE session_date > DATE '2026-09-25') AS n) q;

-- ---------- Relationships (FKs are enforced; these confirm nothing bypassed them) ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'relations', 'enrollments without student/offering', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM enrollments e
        LEFT JOIN students s ON s.student_id = e.student_id
        LEFT JOIN course_offerings o ON o.offering_id = e.offering_id
        WHERE s.student_id IS NULL OR o.offering_id IS NULL) q UNION ALL
SELECT 'relations', 'attendance whose session and enrollment differ in offering', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM attendance_records a
        JOIN class_sessions cs ON cs.session_id = a.session_id
        JOIN enrollments e ON e.enrollment_id = a.enrollment_id
        WHERE cs.offering_id <> e.offering_id) q UNION ALL
SELECT 'relations', 'payments without fee', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM fee_payments p LEFT JOIN fees f ON f.fee_id = p.fee_id
        WHERE f.fee_id IS NULL) q UNION ALL
SELECT 'relations', 'departments without a head', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM departments WHERE head_teacher_id IS NULL) q UNION ALL
SELECT 'relations', 'heads from another department', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM departments d JOIN teachers t ON t.teacher_id = d.head_teacher_id
        WHERE t.department_id <> d.department_id) q UNION ALL
SELECT 'relations', 'advisors from another department', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM students s JOIN teachers t ON t.teacher_id = s.advisor_teacher_id
        WHERE t.department_id <> s.department_id) q UNION ALL
SELECT 'relations', 'offerings taught outside own department', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM course_offerings o
        JOIN courses c ON c.course_id = o.course_id
        JOIN teachers t ON t.teacher_id = o.teacher_id
        WHERE t.department_id <> c.department_id) q UNION ALL
SELECT 'relations', 'core courses taken outside own department', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM enrollments e
        JOIN course_offerings o ON o.offering_id = e.offering_id
        JOIN courses c ON c.course_id = o.course_id
        JOIN students s ON s.student_id = e.student_id
        WHERE c.is_elective = 0 AND c.department_id <> s.department_id) q;

-- ---------- Roles / RBAC foundations ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'rbac', 'ADMIN users', '= 1', n, IF(n = 1, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM users u JOIN roles r ON r.role_id = u.role_id WHERE r.role_code = 'ADMIN') q UNION ALL
SELECT 'rbac', 'HOD users', '= 7', n, IF(n = 7, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM users u JOIN roles r ON r.role_id = u.role_id WHERE r.role_code = 'HOD') q UNION ALL
SELECT 'rbac', 'TEACHER users', '= 33', n, IF(n = 33, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM users u JOIN roles r ON r.role_id = u.role_id WHERE r.role_code = 'TEACHER') q UNION ALL
SELECT 'rbac', 'STUDENT users', '= 1000', n, IF(n = 1000, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM users u JOIN roles r ON r.role_id = u.role_id WHERE r.role_code = 'STUDENT') q UNION ALL
SELECT 'rbac', 'HOD users who do not head a department', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM users u JOIN roles r ON r.role_id = u.role_id
        LEFT JOIN departments d ON d.head_teacher_id = u.teacher_id
        WHERE r.role_code = 'HOD' AND d.department_id IS NULL) q UNION ALL
SELECT 'rbac', 'department heads without a HOD login', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM departments d
        LEFT JOIN users u ON u.teacher_id = d.head_teacher_id AND u.role_id = 2
        WHERE u.user_id IS NULL) q UNION ALL
SELECT 'rbac', 'students/teachers without a login', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT (SELECT COUNT(*) FROM students s LEFT JOIN users u ON u.student_id = s.student_id WHERE u.user_id IS NULL)
             + (SELECT COUNT(*) FROM teachers t LEFT JOIN users u ON u.teacher_id = t.teacher_id WHERE u.user_id IS NULL) AS n) q;

-- ---------- Business rules ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'rules', 'same course twice in one term', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM (
          SELECT e.student_id, o.course_id, o.term_id FROM enrollments e
          JOIN course_offerings o ON o.offering_id = e.offering_id
          GROUP BY e.student_id, o.course_id, o.term_id HAVING COUNT(*) > 1) d) q UNION ALL
SELECT 'rules', 'offerings over capacity', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM (
          SELECT o.offering_id FROM course_offerings o JOIN enrollments e ON e.offering_id = o.offering_id
          GROUP BY o.offering_id, o.capacity HAVING COUNT(*) > o.capacity) d) q UNION ALL
SELECT 'rules', 'grades on non-completed enrollments', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id
        WHERE e.status <> 'COMPLETED') q UNION ALL
SELECT 'rules', 'completed enrollments without a grade', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM enrollments e LEFT JOIN grades g ON g.enrollment_id = e.enrollment_id
        WHERE e.status = 'COMPLETED' AND g.grade_id IS NULL) q UNION ALL
SELECT 'rules', 'letter grade inconsistent with marks', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM grades g
        WHERE g.letter_grade <> (SELECT gs.letter_grade FROM grade_scale gs
                                 WHERE gs.min_marks <= g.marks ORDER BY gs.min_marks DESC LIMIT 1)) q UNION ALL
SELECT 'rules', 'sessions outside their term', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM class_sessions cs
        JOIN course_offerings o ON o.offering_id = cs.offering_id
        JOIN academic_terms t ON t.term_id = o.term_id
        WHERE cs.session_date NOT BETWEEN t.start_date AND t.end_date) q UNION ALL
SELECT 'rules', 'overpaid fees (negative balance)', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM v_fee_balances WHERE balance < 0) q UNION ALL
SELECT 'rules', 'admission year inconsistent with year level', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM students WHERE admission_year <> 2027 - year_level) q UNION ALL
SELECT 'rules', 'exactly one current term', '= 1', n, IF(n = 1, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM academic_terms WHERE is_current = 1) q;

-- ---------- Synthetic-data hygiene ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'synthetic', 'emails outside the reserved .example domain', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT (SELECT COUNT(*) FROM students WHERE email NOT LIKE '%@students.askq-uni.example')
             + (SELECT COUNT(*) FROM teachers WHERE email NOT LIKE '%@staff.askq-uni.example') AS n) q;

-- ---------- MySQL accounts (defence in depth; see accounts/grants.sql) ----------
INSERT INTO verify_results (area, check_name, expected, actual, result)
SELECT 'accounts', 'anonymous MySQL accounts', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.user WHERE User = '') q UNION ALL
SELECT 'accounts', 'ASKQ accounts on a host other than 127.0.0.1', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.user
        WHERE User IN ('askq_reader', 'askq_app') AND Host <> '127.0.0.1') q UNION ALL
SELECT 'accounts', 'ASKQ accounts with any global privilege', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.user
        WHERE User IN ('askq_reader', 'askq_app')
          AND 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv,
                      Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv,
                      References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv,
                      Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv,
                      Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv,
                      Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv,
                      Create_tablespace_priv, Create_role_priv, Drop_role_priv)) q UNION ALL
SELECT 'accounts', 'ASKQ dynamic global / database-level / role grants', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT (SELECT COUNT(*) FROM mysql.global_grants WHERE USER IN ('askq_reader', 'askq_app'))
             + (SELECT COUNT(*) FROM mysql.db WHERE User IN ('askq_reader', 'askq_app'))
             + (SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER IN ('askq_reader', 'askq_app'))
             + (SELECT COUNT(*) FROM mysql.columns_priv WHERE User IN ('askq_reader', 'askq_app'))
             + (SELECT COUNT(*) FROM mysql.procs_priv WHERE User IN ('askq_reader', 'askq_app')) AS n) q UNION ALL
SELECT 'accounts', 'reader grants other than SELECT', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.tables_priv
        WHERE User = 'askq_reader' AND (Table_priv <> 'Select' OR Column_priv <> '')) q UNION ALL
SELECT 'accounts', 'reader grants outside askq_university or on users/roles', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.tables_priv
        WHERE User = 'askq_reader'
          AND (Db <> 'askq_university' OR Table_name IN ('users', 'roles'))) q UNION ALL
SELECT 'accounts', 'reader granted objects (0 before accounts exist)', '0 or 17', n, IF(n IN (0, 17), 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.tables_priv WHERE User = 'askq_reader') q UNION ALL
SELECT 'accounts', 'app grants beyond SELECT/INSERT/UPDATE', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.tables_priv
        WHERE User = 'askq_app'
          AND Table_priv NOT IN ('Select', 'Select,Insert', 'Select,Insert,Update')) q UNION ALL
SELECT 'accounts', 'app UPDATE on append-only tables', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.tables_priv
        WHERE User = 'askq_app' AND FIND_IN_SET('Update', Table_priv) > 0
          AND Table_name IN ('query_history', 'cair_ledger_entries', 'cair_assessments',
                             'cair_audit_findings', 'security_audit_log', 'evaluation_results')) q UNION ALL
SELECT 'accounts', 'app writes to askq_university', '= 0', n, IF(n = 0, 'PASS', 'FAIL')
  FROM (SELECT COUNT(*) n FROM mysql.tables_priv
        WHERE User = 'askq_app' AND Db = 'askq_university' AND Table_priv <> 'Select') q;

SELECT area, check_name, expected, actual, result FROM verify_results ORDER BY check_no;

CREATE TEMPORARY TABLE verify_gate (
    failed_checks INT,
    CONSTRAINT all_database_checks_must_pass CHECK (failed_checks = 0)
);
INSERT INTO verify_gate SELECT COUNT(*) FROM verify_results WHERE result <> 'PASS';
SELECT CONCAT('All ', COUNT(*), ' database checks passed') AS database_verification FROM verify_results;
DROP TEMPORARY TABLE verify_gate;
DROP TEMPORARY TABLE verify_results;
