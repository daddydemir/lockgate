-- Deletion is a tombstone so historical encrypted versions remain immutable.
ALTER TABLE secrets ADD COLUMN archived_at timestamptz;
