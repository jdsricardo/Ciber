CREATE DATABASE IF NOT EXISTS sentinelscope CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sentinelscope;

CREATE TABLE IF NOT EXISTS applications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  base_url VARCHAR(2048) NOT NULL,
  authorization_confirmed_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS analyses (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  application_id BIGINT UNSIGNED NOT NULL,
  status ENUM('running','completed','failed') NOT NULL,
  security_score TINYINT UNSIGNED NULL,
  checks_run SMALLINT UNSIGNED NULL,
  duration_ms INT UNSIGNED NULL,
  http_status SMALLINT UNSIGNED NULL,
  error_message VARCHAR(1000) NULL,
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME NULL,
  CONSTRAINT fk_analysis_application FOREIGN KEY (application_id) REFERENCES applications(id),
  INDEX idx_analysis_application_date (application_id, started_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS findings (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  analysis_id BIGINT UNSIGNED NOT NULL,
  fingerprint VARCHAR(120) NOT NULL,
  title VARCHAR(180) NOT NULL,
  severity ENUM('critical','high','medium','low') NOT NULL,
  affected_url VARCHAR(2048) NOT NULL,
  evidence TEXT NOT NULL,
  developer_impact TEXT NOT NULL,
  remediation TEXT NOT NULL,
  CONSTRAINT fk_finding_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
  INDEX idx_finding_analysis (analysis_id),
  INDEX idx_finding_fingerprint (analysis_id, fingerprint)
) ENGINE=InnoDB;

-- Phase 1 scanner-engine enrichment: category/taxonomy, confidence separate from severity,
-- and finding status. Additive only, so re-running this file against an existing database is safe.
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS category VARCHAR(80) NULL AFTER title,
  ADD COLUMN IF NOT EXISTS cwe VARCHAR(120) NULL AFTER category,
  ADD COLUMN IF NOT EXISTS owasp VARCHAR(120) NULL AFTER cwe,
  ADD COLUMN IF NOT EXISTS wstg VARCHAR(120) NULL AFTER owasp,
  ADD COLUMN IF NOT EXISTS method VARCHAR(10) NULL AFTER affected_url,
  ADD COLUMN IF NOT EXISTS parameter VARCHAR(180) NULL AFTER method,
  ADD COLUMN IF NOT EXISTS parameter_location VARCHAR(40) NULL AFTER parameter,
  ADD COLUMN IF NOT EXISTS confidence TINYINT UNSIGNED NULL AFTER severity,
  ADD COLUMN IF NOT EXISTS status VARCHAR(30) NULL AFTER confidence,
  ADD COLUMN IF NOT EXISTS description TEXT NULL AFTER status,
  ADD COLUMN IF NOT EXISTS evidence_summary VARCHAR(500) NULL AFTER description,
  ADD COLUMN IF NOT EXISTS manual_review_required TINYINT(1) NOT NULL DEFAULT 0 AFTER remediation;

-- Phase 2 active-detection increment: records whether an analysis was passive-only or
-- also ran safe-active probes (SQL injection, XSS, etc.) against discovered parameters.
ALTER TABLE analyses
  ADD COLUMN IF NOT EXISTS mode VARCHAR(20) NOT NULL DEFAULT 'passive' AFTER application_id;

-- Developer-oriented explainability increment: a concrete "vulnerable vs. fixed" code
-- example per finding, so remediation is shown, not just described. Additive only.
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS remediation_example_vulnerable TEXT NULL AFTER remediation,
  ADD COLUMN IF NOT EXISTS remediation_example_fixed TEXT NULL AFTER remediation_example_vulnerable,
  ADD COLUMN IF NOT EXISTS remediation_example_language VARCHAR(60) NULL AFTER remediation_example_fixed,
  ADD COLUMN IF NOT EXISTS remediation_example_note VARCHAR(500) NULL AFTER remediation_example_language;
