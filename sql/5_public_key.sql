--- create
INSERT INTO
  public_keys (
    raw_id,
    identity_id,
    public_key,
    public_key_algorithm
  )
VALUES
  ($1, $2, $3, $4);

--- get_by_identity
SELECT
  raw_id,
  identity_id,
  public_key,
  public_key_algorithm,
  created
FROM
  public_keys
WHERE
  identity_id = $1;
