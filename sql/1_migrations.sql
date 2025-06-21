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
  id VARCHAR PRIMARY KEY NOT NULL,
  identity_id VARCHAR NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  raw_id BYTEA NOT NULL,
  public_key BYTEA NOT NULL,
  public_key_algorithm INT NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW()))
);

CREATE TABLE IF NOT EXISTS challenges (
  id VARCHAR PRIMARY KEY NOT NULL,
  identity_id VARCHAR NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  challenge BYTEA NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  expires TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW()) + '15 minutes'::INTERVAL)
);
