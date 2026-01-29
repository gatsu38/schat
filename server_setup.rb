#!/usr/bin/env ruby
require 'sqlite3'
require 'rbnacl'

CLIENTS_INFO = 'clients_info'
HOST_KEYS = 'host_keys'
EPH_HOST_KEYS = 'host_ephemeral_keys'
MESSAGES = 'messages'
NONCES = 'nonces'
VOUCHERS = 'vouchers'
PREKEYS = 'one_time_prekeys'

# fix the db file
#

db_path = File.join(Dir.pwd, "schat_db", "schat.db")
db_dir = File.join(__dir__, "schat_db")

if File.exist?(db_path)
  puts "A database seems already existing proceeding will delete all the content in the database"
  puts "press Y to continue and create a new db:"
  answer = gets.chomp.strip.upcase
  exit unless answer == "Y"
end

unless Dir.exist?(db_dir)
  FileUtils.mkdir_p(db_dir)
end


db = SQLite3::Database.new(db_path)

# contains all the info about a client included the keys for e2ee client to client
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{CLIENTS_INFO} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE CHECK (
        length(username) BETWEEN 1 AND 20 AND
        username NOT GLOB '*[^A-Za-z0-9]*'
      ),
    signing_public_key BLOB NOT NULL UNIQUE CHECK (length(signing_public_key) = 32),
    identity_public_key BLOB UNIQUE CHECK (identity_public_key IS NULL OR length(identity_public_key) = 32),
    signed_prekey_pub BLOB UNIQUE CHECK (signed_prekey_pub IS NULL OR length(signed_prekey_pub) = 32),
    signed_prekey_sig BLOB UNIQUE CHECK (signed_prekey_sig IS NULL OR length(signed_prekey_sig) = 64),
    spk_created_at TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL


# these are the one time keys of all clients
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{PREKEYS} (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  opk_pub BLOB NOT NULL UNIQUE CHECK (length(opk_pub) = 32),
  counter INTEGER NOT NULL,
  used BOOLEAN default false,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (client_id)
    REFERENCES clients_info(id)
    ON DELETE CASCADE
  );
SQL


# contains the clients messages
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{MESSAGES} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    message BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (recipient_id)
      REFERENCES clients_info(id)
      ON DELETE CASCADE,

    FOREIGN KEY (sender_id)
      REFERENCES clients_info(id)
      ON DELETE CASCADE
  );
SQL


# creates an indexing table for fast messages access
db.execute <<-SQL
  CREATE INDEX IF NOT EXISTS idx_messages_recipient
  ON #{MESSAGES}(recipient_id);
SQL


# contains the nonces for client to server communication
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{NONCES} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce BLOB NOT NULL UNIQUE CHECK (length(nonce) = 15),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL


# the vouchers for user registration
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{VOUCHERS} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voucher BLOB NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    CHECK (length(voucher) = 30)
  );
SQL


# the long term keys for the server
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{HOST_KEYS} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    private_key BLOB NOT NULL UNIQUE CHECK (length(private_key) = 32),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP  
  );
SQL


# the ephemeral keys for the server
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{EPH_HOST_KEYS} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ephemeral_private_key BLOB NOT NULL CHECK (length(ephemeral_private_key) = 32),
    ephemeral_public_key BLOB NOT NULL CHECK (length(ephemeral_public_key) = 32),
    create_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL


    

puts "table #{HOST_KEYS} ready"
puts "table #{EPH_HOST_KEYS} ready"

host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
host_pk = host_sk.verify_key

# insert private and public key inside the database
db.execute("INSERT INTO #{HOST_KEYS} (private_key, public_key) VALUES (?, ?)", [host_sk.to_bytes, host_pk.to_bytes])

# protect database with user password
# !!!!! ADD EXTRA PROTECTION IN THIS PHASE????
# !!!!! ADD PASSWORD MINIMUM SECURITY
#puts "enter password to protect the database"
#user_password = STDIN.noecho(&:gets).chomp

# !!!!! ADD PROTECTION
#password_key = Digest::SHA256.digest(user_password)

#tpm_key = tpm_function

#master_key_bytes = password_key.bytes.zip(tpm_key.bytes).map { |a,b| (a ^ b).chr }.join
#mater_key = RbNaCl::SecretBox.new(master_key_bytes)
db.close
