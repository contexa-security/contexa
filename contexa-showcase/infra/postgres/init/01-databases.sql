-- The portal database is created by POSTGRES_DB. The other databases are created here.
-- showcase_work:   business data shared by every control
-- showcase_engine: Contexa engine metadata (contexa.datasource of control D)
-- showcase_vector: application database of control D that holds the Spring AI vector store
CREATE DATABASE showcase_work;
CREATE DATABASE showcase_engine;
CREATE DATABASE showcase_vector;

\connect showcase_engine
CREATE EXTENSION IF NOT EXISTS vector;

\connect showcase_vector
CREATE EXTENSION IF NOT EXISTS vector;
