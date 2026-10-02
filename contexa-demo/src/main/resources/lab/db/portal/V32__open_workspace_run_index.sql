CREATE INDEX comparison_run_open_workspace ON lab.comparison_run(workspace_id)
    WHERE state IN ('READY','RUNNING');
