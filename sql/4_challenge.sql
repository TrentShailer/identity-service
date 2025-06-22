--- create
-- opt $2
INSERT INTO
  challenges (challenge, identity_id)
VALUES
  ($1, $2)
RETURNING
  challenge,
  identity_id,
  created,
  expires;

--- get
SELECT
  challenge,
  identity_id,
  created,
  expires
FROM
  challenges
WHERE
  challenge = $1;
