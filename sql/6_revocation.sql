--- revoke
INSERT INTO
  revocations (token, expires)
VALUES
  ($1, $2);

--- get_by_token
SELECT
  token,
  expires
FROM
  revocations
WHERE
  token = $1;
