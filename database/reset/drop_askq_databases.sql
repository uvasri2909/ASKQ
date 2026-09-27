-- ============================================================
-- ASKQ: drop the two ASKQ databases (and ONLY those).
--
-- Destroys all ASKQ data, including askq_system history. Run it through
-- database\setup_db.ps1 -Reset, which asks for confirmation first.
-- MySQL accounts are not dropped (the grants file re-applies their privileges).
-- ============================================================

DROP DATABASE IF EXISTS askq_system;
DROP DATABASE IF EXISTS askq_university;
