--- migrate
CREATE TABLE IF NOT EXISTS identities (
  id VARCHAR PRIMARY KEY NOT NULL,
  username VARCHAR UNIQUE NOT NULL,
  display_name VARCHAR NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  expires TIMESTAMP WITH TIME ZONE DEFAULT (timezone('utc', NOW()) + '1 day'::INTERVAL)
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_username_index ON identities (username);

CREATE TABLE IF NOT EXISTS public_keys (
  raw_id VARCHAR PRIMARY KEY NOT NULL,
  identity_id VARCHAR NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  public_key VARCHAR NOT NULL,
  public_key_algorithm INT NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW()))
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge VARCHAR NOT NULL PRIMARY KEY,
  identity_id VARCHAR REFERENCES identities(id) ON DELETE CASCADE,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  expires TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW()) + '15 minutes'::INTERVAL)
);
