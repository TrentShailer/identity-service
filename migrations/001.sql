CREATE TABLE IF NOT EXISTS identities (
  id BYTEA PRIMARY KEY NOT NULL,
  username VARCHAR UNIQUE NOT NULL,
  display_name VARCHAR NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  expires TIMESTAMP WITH TIME ZONE DEFAULT (timezone('utc', NOW()) + '1 day'::INTERVAL)
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_username_index ON identities (username);

CREATE TABLE IF NOT EXISTS public_keys (
  raw_id BYTEA PRIMARY KEY NOT NULL,
  identity_id BYTEA NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
  display_name VARCHAR NOT NULL,
  public_key BYTEA NOT NULL,
  public_key_algorithm INT NOT NULL,
  transports VARCHAR ARRAY NOT NULL,
  signature_counter INT8 NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  last_used TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge BYTEA NOT NULL PRIMARY KEY,
  identity_id BYTEA REFERENCES identities(id) ON DELETE CASCADE,
  origin VARCHAR NOT NULL,
  issued TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  expires TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW()) + '15 minutes'::INTERVAL)
);

CREATE TABLE IF NOT EXISTS revocations (
  token VARCHAR NOT NULL PRIMARY KEY,
  expires TIMESTAMP WITH TIME ZONE NOT NULL
);
