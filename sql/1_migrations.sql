--- migrate
CREATE TABLE IF NOT EXISTS identities (
  id VARCHAR PRIMARY KEY NOT NULL,
  username VARCHAR UNIQUE NOT NULL,
  display_name VARCHAR NOT NULL,
  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (timezone('utc', NOW())),
  expires TIMESTAMP WITH TIME ZONE DEFAULT (timezone('utc', NOW()) + '1 day'::INTERVAL)
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_username_index ON identities (username);
