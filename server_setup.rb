#!/usr/bin/env ruby
require 'sqlite3'
require 'rbnacl'

DB_FILE = '/home/kali/schat_db/schat.db'
HOST_KEYS = 'host_keys'
EPH_HOST_KEYS = 'host_ephemeral_keys'
CLIENTS_INFO = 'clients_info'
CLIENTS_PUB_EPHEMERAL_KEYS = 'clients_eph_pub_keys'
NONCES = 'nonces'
VOUCHERS = 'vouchers'
#if File.exist?(DB_FILE)
#  puts "Database already exists. Exiting"
#  exit
#end

db = SQLite3::Database.new(DB_FILE)

db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{CLIENTS_INFO} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE CHECK (
        length(username) <= 20 AND
        username GLOB '[A-Za-z0-9]*'
      ),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL

db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{CLIENTS_PUB_EPHEMERAL_KEYS} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ephemeral_public_key BLOB NOT NULL CHECK (length(ephemeral_public_key) = 32),
    client_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (client_id)
      REFERENCES clients_info(id)
      ON DELETE CASCADE
  );
SQL

db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{NONCES} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce BLOB NOT NULL UNIQUE CHECK (length(nonce) = 15),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL

db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{VOUCHERS} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voucher BLOB NOT NULL UNIQUE (length(voucher) = 30),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME
  );
SQL

db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{HOST_KEYS} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    private_key BLOB NOT NULL UNIQUE CHECK (length(private_key) = 32),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP  
  );
SQL

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
