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
