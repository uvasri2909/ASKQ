-- ============================================================
-- ASKQ 04: secondary indexes for common query patterns.
--
-- PRIMARY/UNIQUE keys and the indexes backing foreign keys are declared with
-- the tables. Where an index below starts with an FK column, InnoDB drops the
-- implicit single-column FK index it had created, so nothing is duplicated.
-- ============================================================

USE askq_university;

-- Cohort filters: "students in department X, year Y" (also serves the department FK).
CREATE INDEX ix_students_department_year ON students (department_id, year_level);
CREATE INDEX ix_students_admission_year  ON students (admission_year);
CREATE INDEX ix_students_name            ON students (last_name, first_name);

CREATE INDEX ix_teachers_department_designation ON teachers (department_id, designation);
CREATE INDEX ix_teachers_name                   ON teachers (last_name, first_name);

-- "What does teacher T teach this term?" (also serves the teacher FK).
CREATE INDEX ix_offerings_teacher_term ON course_offerings (teacher_id, term_id);
CREATE INDEX ix_offerings_term         ON course_offerings (term_id);

-- Class lists and completion statistics per offering (also serves the offering FK).
CREATE INDEX ix_enrollments_offering_status ON enrollments (offering_id, status);

-- Attendance percentage per enrollment, answered from the index alone
-- (also serves the composite enrollment FK).
CREATE INDEX ix_attendance_enrollment_status ON attendance_records (enrollment_id, offering_id, status);

CREATE INDEX ix_sessions_date ON class_sessions (session_date);

-- Grade distributions (also serves the letter_grade FK).
CREATE INDEX ix_grades_letter ON grades (letter_grade, marks);

-- Fee reports per term and type; overdue lookups.
CREATE INDEX ix_fees_term_type ON fees (term_id, fee_type);
CREATE INDEX ix_fees_due_date  ON fees (due_date);

CREATE INDEX ix_payments_fee_date ON fee_payments (fee_id, paid_on);
CREATE INDEX ix_payments_paid_on  ON fee_payments (paid_on);

-- Recipients of a scholarship in a term (also serves the scholarship FK).
CREATE INDEX ix_awards_scholarship_term ON student_scholarships (scholarship_id, term_id);
CREATE INDEX ix_awards_term_status      ON student_scholarships (term_id, award_status);

USE askq_system;

CREATE INDEX ix_conversations_user_activity ON conversations (user_id, last_activity_at);

CREATE INDEX ix_query_history_user_time   ON query_history (user_id, created_at);
-- A conversation's queries in order (also serves the conversation FK).
CREATE INDEX ix_query_history_conversation ON query_history (conversation_id, created_at);
-- Security dashboards: blocked / denied / rejected queries over time.
CREATE INDEX ix_query_history_status_time ON query_history (final_status, created_at);

-- CAIR reads a user's ledger in order on every query.
CREATE INDEX ix_ledger_user_entry ON cair_ledger_entries (user_id, entry_id);

CREATE INDEX ix_audit_user_time  ON security_audit_log (user_id, occurred_at);
CREATE INDEX ix_audit_event_time ON security_audit_log (event_type, occurred_at);

CREATE INDEX ix_eval_results_run_attack ON evaluation_results (run_id, attack_class);
