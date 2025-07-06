--- clean_expired
DELETE FROM
  identities
WHERE
  expires > timezone('utc', NOW())
RETURNING
  id;

DELETE FROM
  challenges
WHERE
  expires > timezone('utc', NOW());

DELETE FROM
  revocations
WHERE
  expires > timezone('utc', NOW());
