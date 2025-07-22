--- create
INSERT INTO
  public_keys (
    raw_id,
    identity_id,
    display_name,
    public_key,
    public_key_algorithm,
    signature_counter,
    transports
  )
VALUES
  ($1, $2, $3, $4, $5, $6, $7)
RETURNING
  raw_id,
  identity_id,
  display_name,
  public_key,
  public_key_algorithm,
  transports,
  signature_counter,
  created,
  last_used;

--- get_by_identity
SELECT
  raw_id,
  identity_id,
  display_name,
  public_key,
  public_key_algorithm,
  transports,
  signature_counter,
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
  signature_counter,
  created,
  last_used
FROM
  public_keys
WHERE
  raw_id = $1;

--- update_last_used
UPDATE
  public_keys
SET
  last_used = $1,
  signature_counter = $2
WHERE
  raw_id = $3
  AND identity_id = $4;
