--- create
-- opt $2
INSERT INTO
  challenges (challenge, identity_id, origin)
VALUES
  ($1, $2, $3)
RETURNING
  challenge,
  identity_id,
  origin,
  issued,
  expires;

--- take
DELETE FROM
  challenges
WHERE
  challenge = $1
RETURNING
  challenge,
  identity_id,
  origin,
  issued,
  expires;
