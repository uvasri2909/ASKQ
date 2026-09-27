-- ============================================================
-- ASKQ 01: create the two ASKQ databases.
--
-- Deliberately NOT "IF NOT EXISTS": running this against an existing
-- installation fails with error 1007 instead of silently mixing old and new
-- objects. Rebuild with database\setup_db.ps1 -Reset (see database\README.md).
-- ============================================================

-- Organisational data. LLM-generated SQL only ever runs here, as askq_reader.
CREATE DATABASE askq_university
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

-- ASKQ's own data: credentials, conversations, query history, CAIR ledger,
-- audit log, evaluation runs. Written by askq_app; never visible to askq_reader.
CREATE DATABASE askq_system
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;
