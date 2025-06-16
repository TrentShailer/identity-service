--- get_by_username
SELECT
  id,
  username,
  display_name,
  created,
  expires
FROM
  identities
WHERE
  username = $1;

--- create
INSERT INTO
  identities (id, username, display_name)
VALUES
  ($1, $2, $3)
RETURNING
  id,
  username,
  display_name,
  created,
  expires;
