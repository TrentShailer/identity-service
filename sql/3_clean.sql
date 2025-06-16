--- clean_expired
DELETE FROM
  identities
WHERE
  expires > timezone('utc', NOW());
