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

--- get_by_id
SELECT
  id,
  username,
  display_name,
  created,
  expires
FROM
  identities
WHERE
  id = $1;

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

--- delete_by_id
DELETE FROM
  identities
WHERE
  id = $1;
