--- create
INSERT INTO
  public_keys (
    id,
    identity_id,
    raw_id,
    public_key,
    public_key_algorithm
  )
VALUES
  ($1, $2, $3, $4, $5);

--- get_by_identity
SELECT
  id,
  identity_id,
  raw_id,
  public_key,
  public_key_algorithm,
  created
FROM
  public_keys
WHERE
  identity_id = $1;
