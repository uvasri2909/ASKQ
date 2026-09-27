-- ============================================================
-- ASKQ: representative read-only questions against askq_university.
-- The kind of SQL the Phase 5+ pipeline is expected to produce.
-- Safe to run as askq_reader:
--   mysql -h 127.0.0.1 -u askq_reader -p --table < database\validation\sample_queries.sql
-- ============================================================

USE askq_university;

-- 1. Students per department and year.
SELECT d.department_code, s.year_level, COUNT(*) AS students
FROM students s JOIN departments d ON d.department_id = s.department_id
GROUP BY d.department_code, s.year_level
ORDER BY d.department_code, s.year_level;

-- 2. Average Spring 2026 marks and pass rate by department.
SELECT d.department_code,
       ROUND(AVG(g.marks), 1)                               AS avg_marks,
       ROUND(100 * AVG(g.letter_grade <> 'F'), 1)           AS pass_rate_pct
FROM grades g
JOIN enrollments e      ON e.enrollment_id = g.enrollment_id
JOIN students s         ON s.student_id = e.student_id
JOIN departments d      ON d.department_id = s.department_id
GROUP BY d.department_code
ORDER BY avg_marks DESC;

-- 3. Top 5 students by Spring 2026 GPA (credit-weighted).
SELECT s.student_no, CONCAT(s.first_name, ' ', s.last_name) AS name, d.department_code,
       ROUND(SUM(gs.grade_points * c.credits) / SUM(c.credits), 2) AS gpa
FROM grades g
JOIN grade_scale gs      ON gs.letter_grade = g.letter_grade
JOIN enrollments e       ON e.enrollment_id = g.enrollment_id
JOIN course_offerings o  ON o.offering_id = e.offering_id
JOIN courses c           ON c.course_id = o.course_id
JOIN students s          ON s.student_id = e.student_id
JOIN departments d       ON d.department_id = s.department_id
GROUP BY s.student_id, s.student_no, name, d.department_code
ORDER BY gpa DESC, s.student_no
LIMIT 5;

-- 4. Current-term offerings with average attendance below 85%.
SELECT c.course_code, o.section_code, CONCAT(t.first_name, ' ', t.last_name) AS teacher,
       ROUND(AVG(a.attendance_pct), 1) AS avg_attendance_pct
FROM v_attendance_summary a
JOIN course_offerings o ON o.offering_id = a.offering_id
JOIN academic_terms cur ON cur.term_id = o.term_id AND cur.is_current = 1
JOIN courses c          ON c.course_id = o.course_id
JOIN teachers t         ON t.teacher_id = o.teacher_id
GROUP BY c.course_code, o.section_code, teacher
HAVING avg_attendance_pct < 85
ORDER BY avg_attendance_pct
LIMIT 10;

-- 5. Outstanding fees for the current term by department.
SELECT d.department_code,
       COUNT(DISTINCT CASE WHEN b.balance > 0 THEN b.student_id END) AS students_owing,
       SUM(b.balance)                                                AS total_outstanding
FROM v_fee_balances b
JOIN academic_terms t ON t.term_id = b.term_id AND t.is_current = 1
JOIN students s       ON s.student_id = b.student_id
JOIN departments d    ON d.department_id = s.department_id
GROUP BY d.department_code
ORDER BY total_outstanding DESC;

-- 6. Scholarship spend per programme and term.
SELECT sc.scholarship_name, t.term_code, COUNT(*) AS recipients, SUM(a.amount) AS total_awarded
FROM student_scholarships a
JOIN scholarships sc  ON sc.scholarship_id = a.scholarship_id
JOIN academic_terms t ON t.term_id = a.term_id
GROUP BY sc.scholarship_name, t.term_code
ORDER BY t.term_code, total_awarded DESC;

-- 7. Teaching load per teacher in the current term.
SELECT t.employee_no, CONCAT(t.first_name, ' ', t.last_name) AS teacher, d.department_code,
       COUNT(DISTINCT o.offering_id) AS sections, COUNT(e.enrollment_id) AS students
FROM teachers t
JOIN departments d           ON d.department_id = t.department_id
JOIN course_offerings o      ON o.teacher_id = t.teacher_id
JOIN academic_terms cur      ON cur.term_id = o.term_id AND cur.is_current = 1
LEFT JOIN enrollments e      ON e.offering_id = o.offering_id AND e.status <> 'DROPPED'
GROUP BY t.teacher_id, t.employee_no, teacher, d.department_code
ORDER BY students DESC
LIMIT 10;
