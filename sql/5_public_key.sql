--- create
INSERT INTO
  public_keys (
    raw_id,
    identity_id,
    display_name,
    public_key,
    public_key_algorithm,
    transports
  )
VALUES
  ($1, $2, $3, $4, $5, $6);

--- get_by_identity
SELECT
  raw_id,
  identity_id,
  display_name,
  public_key,
  public_key_algorithm,
  transports,
  created,
  last_used
FROM
  public_keys
WHERE
  identity_id = $1;

--- get_by_id
SELECT
  raw_id,
  identity_id,
  display_name,
  public_key,
  public_key_algorithm,
  transports,
  created,
  last_used
FROM
  public_keys
WHERE
  raw_id = $1;

--- update_last_used
-- opt $1
UPDATE
  public_keys
SET
  last_used = $1
WHERE
  raw_id = $2;
