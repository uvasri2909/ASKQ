-- ============================================================
-- ASKQ 02: askq_university schema (organisational data).
--
-- Conventions
--   * InnoDB, utf8mb4 / utf8mb4_0900_ai_ci on every table.
--   * Surrogate integer primary keys; natural keys (codes, numbers) are UNIQUE.
--   * Foreign keys use the default RESTRICT behaviour: nothing cascades, so a
--     mistaken DELETE cannot silently remove grades, fees or attendance.
--   * Enumerated values use VARCHAR + CHECK (portable and readable in errors).
--   * Performance indexes live in 04_indexes.sql; UNIQUE and FK indexes are here.
--   * Role ids are fixed reference data (1 ADMIN, 2 HOD, 3 TEACHER, 4 STUDENT),
--     pinned by roles.ck_roles_id_code; users.ck_users_role_links relies on them.
--   * Sensitive attributes (salary, date of birth, gender, fees, payments,
--     scholarships) live once, in their normalised tables. Role-specific
--     visibility is enforced by the backend (RBAC + SQL validation), not by
--     duplicating data; askq_reader's grants are defence in depth.
-- ============================================================

USE askq_university;

-- ---------- Reference data ----------

CREATE TABLE roles (
    role_id      TINYINT UNSIGNED NOT NULL,
    role_code    VARCHAR(20)      NOT NULL,
    role_name    VARCHAR(50)      NOT NULL,
    description  VARCHAR(255)     NOT NULL,
    created_at   TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id),
    UNIQUE KEY uq_roles_code (role_code),
    -- Pins each id to its code, because ck_users_role_links (below) and the
    -- backend refer to roles by these ids.
    CONSTRAINT ck_roles_id_code CHECK (
           (role_id = 1 AND role_code = 'ADMIN')
        OR (role_id = 2 AND role_code = 'HOD')
        OR (role_id = 3 AND role_code = 'TEACHER')
        OR (role_id = 4 AND role_code = 'STUDENT'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='Application roles used by backend RBAC';

CREATE TABLE departments (
    department_id     SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    department_code   VARCHAR(10)       NOT NULL,
    department_name   VARCHAR(100)      NOT NULL,
    building          VARCHAR(100)      NOT NULL,
    established_year  SMALLINT UNSIGNED NOT NULL,
    -- Head of department. Nullable because departments are loaded before
    -- teachers; the FK is added after the teachers table below.
    head_teacher_id   INT UNSIGNED      NULL,
    created_at        TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (department_id),
    UNIQUE KEY uq_departments_code (department_code),
    UNIQUE KEY uq_departments_name (department_name),
    UNIQUE KEY uq_departments_head (head_teacher_id),
    CONSTRAINT ck_departments_code CHECK (REGEXP_LIKE(department_code, '^[A-Z]{2,10}$', 'c')),
    CONSTRAINT ck_departments_year CHECK (established_year BETWEEN 1900 AND 2100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE academic_terms (
    term_id        SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    term_code      VARCHAR(12)       NOT NULL,
    term_name      VARCHAR(50)       NOT NULL,
    academic_year  CHAR(9)           NOT NULL,
    season         VARCHAR(6)        NOT NULL,
    start_date     DATE              NOT NULL,
    end_date       DATE              NOT NULL,
    is_current     TINYINT(1)        NOT NULL DEFAULT 0,
    -- 1 for the current term, NULL otherwise: the UNIQUE key below then allows
    -- at most one current term.
    current_marker TINYINT(1) GENERATED ALWAYS AS (IF(is_current = 1, 1, NULL)) STORED,
    created_at     TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (term_id),
    UNIQUE KEY uq_terms_code (term_code),
    UNIQUE KEY uq_terms_year_season (academic_year, season),
    UNIQUE KEY uq_terms_single_current (current_marker),
    CONSTRAINT ck_terms_dates   CHECK (end_date > start_date),
    CONSTRAINT ck_terms_season  CHECK (season IN ('SPRING', 'SUMMER', 'FALL')),
    CONSTRAINT ck_terms_year    CHECK (REGEXP_LIKE(academic_year, '^[0-9]{4}-[0-9]{4}$')),
    CONSTRAINT ck_terms_current CHECK (is_current IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE grade_scale (
    letter_grade  VARCHAR(2)   NOT NULL,
    min_marks     DECIMAL(5,2) NOT NULL,
    grade_points  DECIMAL(3,2) NOT NULL,
    description   VARCHAR(50)  NOT NULL,
    PRIMARY KEY (letter_grade),
    UNIQUE KEY uq_grade_scale_min (min_marks),
    CONSTRAINT ck_grade_scale_min    CHECK (min_marks BETWEEN 0 AND 100),
    CONSTRAINT ck_grade_scale_points CHECK (grade_points BETWEEN 0 AND 4)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  COMMENT='A letter applies to marks >= min_marks and below the next higher min_marks';

-- ---------- People ----------

CREATE TABLE teachers (
    teacher_id     INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    employee_no    VARCHAR(10)       NOT NULL,
    first_name     VARCHAR(50)       NOT NULL,
    last_name      VARCHAR(50)       NOT NULL,
    email          VARCHAR(255)      NOT NULL,
    department_id  SMALLINT UNSIGNED NOT NULL,
    designation    VARCHAR(30)       NOT NULL,
    hire_date      DATE              NOT NULL,
    annual_salary  DECIMAL(10,2)     NOT NULL,
    is_active      TINYINT(1)        NOT NULL DEFAULT 1,
    created_at     TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (teacher_id),
    UNIQUE KEY uq_teachers_employee_no (employee_no),
    UNIQUE KEY uq_teachers_email (email),
    CONSTRAINT fk_teachers_department FOREIGN KEY (department_id)
        REFERENCES departments (department_id),
    CONSTRAINT ck_teachers_employee_no CHECK (REGEXP_LIKE(employee_no, '^T[0-9]{4}$', 'c')),
    CONSTRAINT ck_teachers_designation CHECK (designation IN
        ('Professor', 'Associate Professor', 'Assistant Professor', 'Lecturer')),
    CONSTRAINT ck_teachers_salary      CHECK (annual_salary > 0),
    CONSTRAINT ck_teachers_active      CHECK (is_active IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE departments
    ADD CONSTRAINT fk_departments_head FOREIGN KEY (head_teacher_id)
        REFERENCES teachers (teacher_id);

CREATE TABLE students (
    student_id          INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    student_no          VARCHAR(12)       NOT NULL,
    first_name          VARCHAR(50)       NOT NULL,
    last_name           VARCHAR(50)       NOT NULL,
    email               VARCHAR(255)      NOT NULL,
    gender              CHAR(1)           NOT NULL,
    date_of_birth       DATE              NOT NULL,
    department_id       SMALLINT UNSIGNED NOT NULL,
    admission_year      SMALLINT UNSIGNED NOT NULL,
    year_level          TINYINT UNSIGNED  NOT NULL,
    residency_status    VARCHAR(13)       NOT NULL,
    home_region         VARCHAR(50)       NOT NULL,
    is_hostel_resident  TINYINT(1)        NOT NULL DEFAULT 0,
    advisor_teacher_id  INT UNSIGNED      NULL,
    enrollment_status   VARCHAR(10)       NOT NULL DEFAULT 'ACTIVE',
    created_at          TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (student_id),
    UNIQUE KEY uq_students_student_no (student_no),
    UNIQUE KEY uq_students_email (email),
    CONSTRAINT fk_students_department FOREIGN KEY (department_id)
        REFERENCES departments (department_id),
    CONSTRAINT fk_students_advisor FOREIGN KEY (advisor_teacher_id)
        REFERENCES teachers (teacher_id),
    CONSTRAINT ck_students_student_no CHECK (REGEXP_LIKE(student_no, '^S[0-9]{8}$', 'c')),
    CONSTRAINT ck_students_gender     CHECK (gender IN ('F', 'M', 'X')),
    CONSTRAINT ck_students_admission  CHECK (admission_year BETWEEN 2000 AND 2100),
    CONSTRAINT ck_students_dob        CHECK (YEAR(date_of_birth) < admission_year - 10),
    CONSTRAINT ck_students_year_level CHECK (year_level BETWEEN 1 AND 4),
    CONSTRAINT ck_students_residency  CHECK (residency_status IN ('DOMESTIC', 'INTERNATIONAL')),
    CONSTRAINT ck_students_hostel     CHECK (is_hostel_resident IN (0, 1)),
    CONSTRAINT ck_students_status     CHECK (enrollment_status IN
        ('ACTIVE', 'ON_LEAVE', 'SUSPENDED', 'WITHDRAWN', 'GRADUATED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Login identities. Exactly one of: nothing (ADMIN), a teacher (HOD/TEACHER)
-- or a student (STUDENT). Names/emails are not duplicated here; they come from
-- the linked teacher/student row. Password hashes are NOT stored in this
-- database (see askq_system.app_user_credentials), and askq_reader has no
-- privilege on this table.
CREATE TABLE users (
    user_id     INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    username    VARCHAR(50)      NOT NULL,
    role_id     TINYINT UNSIGNED NOT NULL,
    teacher_id  INT UNSIGNED     NULL,
    student_id  INT UNSIGNED     NULL,
    is_active   TINYINT(1)       NOT NULL DEFAULT 1,
    created_at  TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_teacher (teacher_id),
    UNIQUE KEY uq_users_student (student_id),
    CONSTRAINT fk_users_role    FOREIGN KEY (role_id)    REFERENCES roles (role_id),
    CONSTRAINT fk_users_teacher FOREIGN KEY (teacher_id) REFERENCES teachers (teacher_id),
    CONSTRAINT fk_users_student FOREIGN KEY (student_id) REFERENCES students (student_id),
    CONSTRAINT ck_users_username CHECK (REGEXP_LIKE(username, '^[a-z0-9._-]{3,50}$', 'c')),
    CONSTRAINT ck_users_active   CHECK (is_active IN (0, 1)),
    CONSTRAINT ck_users_role_links CHECK (
           (role_id = 1       AND teacher_id IS NULL     AND student_id IS NULL)
        OR (role_id IN (2, 3) AND teacher_id IS NOT NULL AND student_id IS NULL)
        OR (role_id = 4       AND teacher_id IS NULL     AND student_id IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------- Teaching ----------

CREATE TABLE courses (
    course_id      SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    course_code    VARCHAR(10)       NOT NULL,
    title          VARCHAR(150)      NOT NULL,
    department_id  SMALLINT UNSIGNED NOT NULL,
    course_level   SMALLINT UNSIGNED NOT NULL,
    credits        TINYINT UNSIGNED  NOT NULL,
    is_elective    TINYINT(1)        NOT NULL DEFAULT 0,
    is_active      TINYINT(1)        NOT NULL DEFAULT 1,
    created_at     TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (course_id),
    UNIQUE KEY uq_courses_code (course_code),
    UNIQUE KEY uq_courses_department_title (department_id, title),
    CONSTRAINT fk_courses_department FOREIGN KEY (department_id)
        REFERENCES departments (department_id),
    CONSTRAINT ck_courses_code     CHECK (REGEXP_LIKE(course_code, '^[A-Z]{2,5}[0-9]{3}$', 'c')),
    CONSTRAINT ck_courses_level    CHECK (course_level IN (100, 200, 300, 400)),
    CONSTRAINT ck_courses_credits  CHECK (credits BETWEEN 1 AND 6),
    CONSTRAINT ck_courses_elective CHECK (is_elective IN (0, 1)),
    CONSTRAINT ck_courses_active   CHECK (is_active IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One section of a course, taught by one teacher in one term.
CREATE TABLE course_offerings (
    offering_id   INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    course_id     SMALLINT UNSIGNED NOT NULL,
    term_id       SMALLINT UNSIGNED NOT NULL,
    section_code  CHAR(1)           NOT NULL,
    teacher_id    INT UNSIGNED      NOT NULL,
    capacity      SMALLINT UNSIGNED NOT NULL,
    room          VARCHAR(30)       NOT NULL,
    created_at    TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (offering_id),
    UNIQUE KEY uq_offerings_course_term_section (course_id, term_id, section_code),
    CONSTRAINT fk_offerings_course  FOREIGN KEY (course_id)  REFERENCES courses (course_id),
    CONSTRAINT fk_offerings_term    FOREIGN KEY (term_id)    REFERENCES academic_terms (term_id),
    CONSTRAINT fk_offerings_teacher FOREIGN KEY (teacher_id) REFERENCES teachers (teacher_id),
    CONSTRAINT ck_offerings_section  CHECK (REGEXP_LIKE(section_code, '^[A-Z]$', 'c')),
    CONSTRAINT ck_offerings_capacity CHECK (capacity BETWEEN 1 AND 500)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE enrollments (
    enrollment_id  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    student_id     INT UNSIGNED NOT NULL,
    offering_id    INT UNSIGNED NOT NULL,
    enrolled_on    DATE         NOT NULL,
    status         VARCHAR(10)  NOT NULL DEFAULT 'ENROLLED',
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (enrollment_id),
    UNIQUE KEY uq_enrollments_student_offering (student_id, offering_id),
    -- Target of the composite FK from attendance_records.
    UNIQUE KEY uq_enrollments_id_offering (enrollment_id, offering_id),
    CONSTRAINT fk_enrollments_student  FOREIGN KEY (student_id)  REFERENCES students (student_id),
    CONSTRAINT fk_enrollments_offering FOREIGN KEY (offering_id) REFERENCES course_offerings (offering_id),
    CONSTRAINT ck_enrollments_status CHECK (status IN ('ENROLLED', 'COMPLETED', 'DROPPED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Final grade of a completed enrollment. letter_grade is the officially
-- recorded grade (a fact), not a cache of min_marks.
CREATE TABLE grades (
    grade_id       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    enrollment_id  INT UNSIGNED NOT NULL,
    marks          DECIMAL(5,2) NOT NULL,
    letter_grade   VARCHAR(2)   NOT NULL,
    graded_on      DATE         NOT NULL,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (grade_id),
    UNIQUE KEY uq_grades_enrollment (enrollment_id),
    CONSTRAINT fk_grades_enrollment FOREIGN KEY (enrollment_id) REFERENCES enrollments (enrollment_id),
    CONSTRAINT fk_grades_letter     FOREIGN KEY (letter_grade)  REFERENCES grade_scale (letter_grade),
    CONSTRAINT ck_grades_marks CHECK (marks BETWEEN 0 AND 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- A scheduled class meeting of an offering.
CREATE TABLE class_sessions (
    session_id    INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    offering_id   INT UNSIGNED      NOT NULL,
    session_no    SMALLINT UNSIGNED NOT NULL,
    session_date  DATE              NOT NULL,
    created_at    TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id),
    UNIQUE KEY uq_sessions_offering_no (offering_id, session_no),
    UNIQUE KEY uq_sessions_offering_date (offering_id, session_date),
    -- Target of the composite FK from attendance_records.
    UNIQUE KEY uq_sessions_id_offering (session_id, offering_id),
    CONSTRAINT fk_sessions_offering FOREIGN KEY (offering_id) REFERENCES course_offerings (offering_id),
    CONSTRAINT ck_sessions_no CHECK (session_no >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One row per (session, enrolled student). offering_id is carried so that two
-- composite foreign keys can guarantee the session and the enrollment belong to
-- the SAME offering (a student cannot be marked in a class they don't take).
CREATE TABLE attendance_records (
    attendance_id  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id     INT UNSIGNED    NOT NULL,
    enrollment_id  INT UNSIGNED    NOT NULL,
    offering_id    INT UNSIGNED    NOT NULL,
    status         VARCHAR(7)      NOT NULL,
    created_at     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (attendance_id),
    UNIQUE KEY uq_attendance_session_enrollment (session_id, enrollment_id),
    CONSTRAINT fk_attendance_session FOREIGN KEY (session_id, offering_id)
        REFERENCES class_sessions (session_id, offering_id),
    CONSTRAINT fk_attendance_enrollment FOREIGN KEY (enrollment_id, offering_id)
        REFERENCES enrollments (enrollment_id, offering_id),
    CONSTRAINT ck_attendance_status CHECK (status IN ('PRESENT', 'ABSENT', 'LATE', 'EXCUSED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------- Finance ----------

-- A charge raised against a student for a term. Balances are derived from
-- fee_payments (see view v_fee_balances), never stored.
CREATE TABLE fees (
    fee_id      INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    student_id  INT UNSIGNED      NOT NULL,
    term_id     SMALLINT UNSIGNED NOT NULL,
    fee_type    VARCHAR(10)       NOT NULL,
    amount      DECIMAL(10,2)     NOT NULL,
    due_date    DATE              NOT NULL,
    created_at  TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (fee_id),
    UNIQUE KEY uq_fees_student_term_type (student_id, term_id, fee_type),
    CONSTRAINT fk_fees_student FOREIGN KEY (student_id) REFERENCES students (student_id),
    CONSTRAINT fk_fees_term    FOREIGN KEY (term_id)    REFERENCES academic_terms (term_id),
    CONSTRAINT ck_fees_type   CHECK (fee_type IN ('TUITION', 'LAB', 'LIBRARY', 'EXAM', 'HOSTEL')),
    CONSTRAINT ck_fees_amount CHECK (amount > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE fee_payments (
    payment_id      INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    fee_id          INT UNSIGNED  NOT NULL,
    amount          DECIMAL(10,2) NOT NULL,
    paid_on         DATE          NOT NULL,
    payment_method  VARCHAR(13)   NOT NULL,
    receipt_no      VARCHAR(20)   NOT NULL,
    created_at      TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (payment_id),
    UNIQUE KEY uq_payments_receipt (receipt_no),
    CONSTRAINT fk_payments_fee FOREIGN KEY (fee_id) REFERENCES fees (fee_id),
    CONSTRAINT ck_payments_amount CHECK (amount > 0),
    CONSTRAINT ck_payments_method CHECK (payment_method IN ('BANK_TRANSFER', 'CARD', 'CASH', 'CHEQUE'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Scholarship programmes (catalogue).
CREATE TABLE scholarships (
    scholarship_id    SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scholarship_code  VARCHAR(20)       NOT NULL,
    scholarship_name  VARCHAR(100)      NOT NULL,
    category          VARCHAR(13)       NOT NULL,
    sponsor           VARCHAR(100)      NOT NULL,
    -- NULL = open to all departments.
    department_id     SMALLINT UNSIGNED NULL,
    standard_amount   DECIMAL(10,2)     NOT NULL,
    is_active         TINYINT(1)        NOT NULL DEFAULT 1,
    created_at        TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (scholarship_id),
    UNIQUE KEY uq_scholarships_code (scholarship_code),
    UNIQUE KEY uq_scholarships_name (scholarship_name),
    CONSTRAINT fk_scholarships_department FOREIGN KEY (department_id)
        REFERENCES departments (department_id),
    CONSTRAINT ck_scholarships_category CHECK (category IN
        ('MERIT', 'NEED_BASED', 'ATHLETIC', 'INTERNATIONAL', 'RESEARCH')),
    CONSTRAINT ck_scholarships_amount   CHECK (standard_amount > 0),
    CONSTRAINT ck_scholarships_active   CHECK (is_active IN (0, 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- A scholarship awarded to a student for one term.
CREATE TABLE student_scholarships (
    award_id        INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    student_id      INT UNSIGNED      NOT NULL,
    scholarship_id  SMALLINT UNSIGNED NOT NULL,
    term_id         SMALLINT UNSIGNED NOT NULL,
    amount          DECIMAL(10,2)     NOT NULL,
    award_status    VARCHAR(9)        NOT NULL,
    awarded_on      DATE              NOT NULL,
    created_at      TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (award_id),
    UNIQUE KEY uq_awards_student_scholarship_term (student_id, scholarship_id, term_id),
    CONSTRAINT fk_awards_student     FOREIGN KEY (student_id)     REFERENCES students (student_id),
    CONSTRAINT fk_awards_scholarship FOREIGN KEY (scholarship_id) REFERENCES scholarships (scholarship_id),
    CONSTRAINT fk_awards_term        FOREIGN KEY (term_id)        REFERENCES academic_terms (term_id),
    CONSTRAINT ck_awards_amount CHECK (amount > 0),
    CONSTRAINT ck_awards_status CHECK (award_status IN ('ACTIVE', 'COMPLETED', 'REVOKED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
