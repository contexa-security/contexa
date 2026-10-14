-- The company time of each export (LU-2 fix). started_at is the wall clock of the business service, while an
-- approval's validity and a request's time are company times; an approval's use counts the exports whose company
-- time falls in its validity before the request. NULL for exports recorded before this column.
ALTER TABLE export_job ADD COLUMN company_at TIMESTAMP WITH TIME ZONE;
