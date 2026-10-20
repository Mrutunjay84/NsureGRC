"""H-11: checkpoint continuity (docs/AUDIT_COMPLETENESS.md).

audit.checkpoint gains format version 2: a per-stream `cp_index` (1,2,3 ... gapless) and `prev_cp_digest` (digest of the previous signed checkpoint).
* Legacy rows (format 1, from before this release) stay verifiable and are counted as `legacy`; NEW format-1 inserts are refused (no downgrade).
* The primary key moves to a surrogate `cp_id` because heartbeat checkpoints repeat a `seq` (no new events, new checkpoint).
* A BEFORE INSERT trigger makes the sealer role unable to skip, repeat or rewind an index, or to move `seq` backwards. It does not replace the
  verifier (a schema owner can disable triggers); it stops mistakes and a merely-compromised sealer credential.
Runs as ngrc_owner using SET LOCAL ROLE ngrc_audit_owner (the reviewed audit migration path).
"""
from django.db import migrations

FORWARD = [
    "SET LOCAL ROLE ngrc_audit_owner",
    "ALTER TABLE audit.checkpoint ADD COLUMN cp_id bigint GENERATED ALWAYS AS IDENTITY",
    "ALTER TABLE audit.checkpoint DROP CONSTRAINT checkpoint_pkey",
    "ALTER TABLE audit.checkpoint ADD PRIMARY KEY (cp_id)",
    "ALTER TABLE audit.checkpoint ADD COLUMN format_version int NOT NULL DEFAULT 1 CHECK (format_version IN (1, 2))",
    "ALTER TABLE audit.checkpoint ADD COLUMN cp_index bigint",
    "ALTER TABLE audit.checkpoint ADD COLUMN prev_cp_digest bytea",
    """ALTER TABLE audit.checkpoint ADD CONSTRAINT checkpoint_format_shape CHECK (
  (format_version = 1 AND cp_index IS NULL AND prev_cp_digest IS NULL)
  OR (format_version = 2 AND cp_index >= 1 AND prev_cp_digest IS NOT NULL AND octet_length(prev_cp_digest) = 32))""",
    "CREATE UNIQUE INDEX checkpoint_v1_seq ON audit.checkpoint (stream_key, seq) WHERE format_version = 1",
    "CREATE UNIQUE INDEX checkpoint_v2_index ON audit.checkpoint (stream_key, cp_index) WHERE format_version = 2",
    """CREATE FUNCTION audit.checkpoint_continuity() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE prev record;
BEGIN
  IF NEW.format_version <> 2 THEN
    RAISE EXCEPTION 'legacy checkpoint format is closed; new checkpoints must be format 2' USING ERRCODE = '42501';
  END IF;
  SELECT cp_index, seq INTO prev FROM audit.checkpoint
    WHERE stream_key = NEW.stream_key AND format_version = 2 ORDER BY cp_index DESC LIMIT 1;
  IF NOT FOUND THEN
    IF NEW.cp_index <> 1 THEN
      RAISE EXCEPTION 'first checkpoint of a stream must have index 1' USING ERRCODE = '42501';
    END IF;
  ELSIF NEW.cp_index <> prev.cp_index + 1 THEN
    RAISE EXCEPTION 'checkpoint index must advance by exactly one' USING ERRCODE = '42501';
  ELSIF NEW.seq < prev.seq THEN
    RAISE EXCEPTION 'checkpoint seq may not move backwards' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER checkpoint_continuity BEFORE INSERT ON audit.checkpoint FOR EACH ROW EXECUTE FUNCTION audit.checkpoint_continuity()",
    "RESET ROLE",
]

# Not reversible: format-2 rows cannot be represented in the old shape, and audit data is append-only by design.


class Migration(migrations.Migration):
    dependencies = [("audit", "0003_registry_p2")]
    operations = [migrations.RunSQL(FORWARD)]
