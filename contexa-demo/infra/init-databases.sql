-- Dedicated demo databases only. No existing Contexa database is accessed.
CREATE DATABASE lab_baseline;
CREATE DATABASE lab_contexa;
CREATE DATABASE lab_security;
\connect lab_security
CREATE EXTENSION IF NOT EXISTS vector;
