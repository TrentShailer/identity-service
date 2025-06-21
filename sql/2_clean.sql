--- clean_expired
DELETE FROM
  identities
WHERE
  expires > timezone('utc', NOW());

DELETE FROM
  challenges
WHERE
  expires > timezone('utc', NOW());
