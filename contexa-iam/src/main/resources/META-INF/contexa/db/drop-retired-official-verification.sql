-- Contexa: removes the tables of the retired official verification (58 tables).
-- Run it only after the application has been upgraded to the version without the official verification:
-- an older version treats a database without these tables as a partial installation and refuses to start.
-- Contexa never runs this file itself (it is not one of the schema or seed files run at startup): run it by hand,
-- for example psql -f drop-retired-official-verification.sql, against the Contexa database.
BEGIN;
DROP TABLE IF EXISTS ctxa_verification_execution_request_ledger;
DROP TABLE IF EXISTS ctxa_verification_execution_preflight_ledger;
DROP TABLE IF EXISTS ctxa_verification_case_ledger;
DROP TABLE IF EXISTS ctxa_evaluation_case_ledger;
DROP TABLE IF EXISTS ctxa_unified_truth_audit_ledger;
DROP TABLE IF EXISTS ctxa_published_benchmark_release;
DROP TABLE IF EXISTS ctxa_verification_run_round_ledger;
DROP TABLE IF EXISTS ctxa_verification_run_check_ledger;
DROP TABLE IF EXISTS ctxa_verification_run_fact_ledger;
DROP TABLE IF EXISTS ctxa_verification_run_event_ledger;
DROP TABLE IF EXISTS ctxa_verification_raw_evidence_artifact_ledger;
DROP TABLE IF EXISTS ctxa_official_verification_run_batch;
DROP TABLE IF EXISTS ctxa_official_verification_metric_snapshot;
DROP TABLE IF EXISTS ctxa_official_verification_operator_finding;
DROP TABLE IF EXISTS ctxa_official_verification_operator_remediation_group;
DROP TABLE IF EXISTS ctxa_official_verification_reverify_result;
DROP TABLE IF EXISTS ctxa_official_verification_audit_snapshot;
DROP TABLE IF EXISTS ctxa_official_verification_prompt_comparison;
DROP TABLE IF EXISTS ctxa_official_actual_prompt_problem_ledger;
DROP TABLE IF EXISTS ctxa_official_verification_execution_lock;
DROP TABLE IF EXISTS ctxa_official_verification_execution_state_history;
DROP TABLE IF EXISTS ctxa_official_verification_metric_execution_ledger;
DROP TABLE IF EXISTS ctxa_official_verification_metric_definition;
DROP TABLE IF EXISTS ctxa_official_verification_metric_check_definition;
DROP TABLE IF EXISTS ctxa_official_verification_metric_regression_package;
DROP TABLE IF EXISTS ctxa_official_verification_metric_regression_expectation;
DROP TABLE IF EXISTS ctxa_official_prompt_field_definition;
DROP TABLE IF EXISTS ctxa_official_prompt_field_state_ledger;
DROP TABLE IF EXISTS ctxa_official_prompt_projection_ledger;
DROP TABLE IF EXISTS ctxa_official_prompt_generation_lineage;
DROP TABLE IF EXISTS ctxa_official_prompt_field_value_ledger;
DROP TABLE IF EXISTS ctxa_official_prompt_field_diff_ledger;
DROP TABLE IF EXISTS ctxa_official_prompt_signal_ledger;
DROP TABLE IF EXISTS ctxa_official_metric_contract_version;
DROP TABLE IF EXISTS ctxa_official_metric_purpose_contract;
DROP TABLE IF EXISTS ctxa_official_metric_signal_contract;
DROP TABLE IF EXISTS ctxa_official_metric_input_contract;
DROP TABLE IF EXISTS ctxa_official_metric_evaluation_contract;
DROP TABLE IF EXISTS ctxa_official_prompt_signal_contract;
DROP TABLE IF EXISTS ctxa_official_metric_customer_message_contract;
DROP TABLE IF EXISTS ctxa_official_metric_customer_display_contract;
DROP TABLE IF EXISTS ctxa_official_metric_customer_display_binding;
DROP TABLE IF EXISTS ctxa_official_metric_check_display_evidence_contract;
DROP TABLE IF EXISTS ctxa_official_metric_input_readiness_ledger;
DROP TABLE IF EXISTS ctxa_official_metric_purpose_evaluation_ledger;
DROP TABLE IF EXISTS ctxa_official_metric_purpose_evidence_ledger;
DROP TABLE IF EXISTS ctxa_official_metric_customer_display_payload;
DROP TABLE IF EXISTS ctxa_prompt_runtime_metric_check_slot_contract;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_resource_status;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_issuance_audit;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_baseline_seed_ledger;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_baseline_readiness_ledger;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_rag_readiness_ledger;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_issuance_batch_item;
DROP TABLE IF EXISTS ctxa_verification_run_ledger;
DROP TABLE IF EXISTS ctxa_prompt_runtime_slot_contract;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_baseline_requirement_contract;
DROP TABLE IF EXISTS ctxa_pqa_sealed_evidence_issuance_batch;
DROP FUNCTION IF EXISTS contexa_sync_verification_fact_jsonb();
DROP FUNCTION IF EXISTS contexa_sync_verification_run_ledger_jsonb();
-- contexa_safe_jsonb() and contexa_sync_sealed_evidence_jsonb() stay: the sealed evidence table uses them.
COMMIT;
