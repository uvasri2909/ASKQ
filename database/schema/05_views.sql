-- ============================================================
-- ASKQ 05: derived views in askq_university.
--
-- Values that are computed rather than stored (fee balances, attendance
-- rates) are exposed as views so they are never duplicated in base tables.
--
-- SQL SECURITY INVOKER: a view runs with the privileges of whoever queries
-- it, so it can never be used to reach data the caller's grants don't allow.
-- askq_reader therefore needs SELECT on the underlying tables as well, which
-- it has (accounts/grants.sql).
--
-- DEFINER = CURRENT_USER: the admin account running setup, which by
-- definition exists on this installation. No named account (such as
-- mysql.sys) is assumed to exist, and no SET_USER_ID privilege is needed.
-- With INVOKER security the definer grants nothing at query time.
--
-- Deterministic: no CURRENT_DATE / NOW(). Time-dependent logic uses the
-- dataset reference date DATE '2026-09-25' (= DATA_AS_OF in
-- seed/askq_seed/reference.py; a test keeps the two identical).
-- ============================================================

USE askq_university;

-- Outstanding amount per fee, judged as of the dataset reference date.
CREATE DEFINER = CURRENT_USER SQL SECURITY INVOKER
VIEW v_fee_balances AS
SELECT
    f.fee_id,
    f.student_id,
    f.term_id,
    f.fee_type,
    f.amount                                   AS amount_due,
    COALESCE(p.amount_paid, 0)                 AS amount_paid,
    f.amount - COALESCE(p.amount_paid, 0)      AS balance,
    f.due_date,
    DATE '2026-09-25'                          AS status_as_of,
    CASE
        WHEN COALESCE(p.amount_paid, 0) >= f.amount THEN 'PAID'
        WHEN f.due_date < DATE '2026-09-25'        THEN 'OVERDUE'
        WHEN COALESCE(p.amount_paid, 0) > 0        THEN 'PARTIAL'
        ELSE 'UNPAID'
    END                                        AS payment_status
FROM fees f
LEFT JOIN (
    SELECT fee_id, SUM(amount) AS amount_paid
    FROM fee_payments
    GROUP BY fee_id
) p ON p.fee_id = f.fee_id;

-- Attendance per enrollment. LATE counts as attended; EXCUSED absences are
-- excluded from the denominator.
CREATE DEFINER = CURRENT_USER SQL SECURITY INVOKER
VIEW v_attendance_summary AS
SELECT
    e.enrollment_id,
    e.student_id,
    e.offering_id,
    COUNT(a.attendance_id)                                     AS sessions_recorded,
    COALESCE(SUM(a.status IN ('PRESENT', 'LATE')), 0)          AS sessions_attended,
    COALESCE(SUM(a.status = 'ABSENT'), 0)                      AS sessions_absent,
    COALESCE(SUM(a.status = 'EXCUSED'), 0)                     AS sessions_excused,
    ROUND(100 * SUM(a.status IN ('PRESENT', 'LATE'))
          / NULLIF(SUM(a.status <> 'EXCUSED'), 0), 1)          AS attendance_pct
FROM enrollments e
LEFT JOIN attendance_records a ON a.enrollment_id = e.enrollment_id
GROUP BY e.enrollment_id, e.student_id, e.offering_id;
