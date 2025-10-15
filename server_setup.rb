#!/usr/bin/env ruby
require 'sqlite3'
require 'rbnacl'

DB_FILE = '~/schat.db'
TABLE_NAME = 'host_keys.db'

if File.exists?(DB_FILE)
  puts "Database already exists. Exiting"
  exit
end

db = SQLite3::Database.new(DB_FILE)

db.execute <<-SQL
  CREATE TABLE IF NOT EXIST #{TABLE_NAME} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT TIMESTAMP  
  );
SQL

puts "table #{TABLE_NAME} ready"

host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
host_pk = host_sk.verify_key

# insert private and public key inside the database
db.execute(INSERT INTO #{TABLE_NAME} (private_key, public_key) VALUES (?, ?)", [host_sk.to_bytes, host_pk.to_bytes])

# protect database with user password
# !!!!! ADD EXTRA PROTECTION IN THIS PHASE????
# !!!!! ADD PASSWORD MINIMUM SECURITY
puts "enter password to protect the database"
user_password = STDIN.noecho(&:gets).chomp

# !!!!! ADD PROTECTION
password_key = Digest::SHA256.digest(user_password)

tpm_key = tpm_function

master_key_bytes = password_key.bytes.zip(tpm_key.bytes).map { |a,b| (a ^ b).chr }.join
mater_key = RbNaCl::SecretBox.new(master_key_bytes)
db.close
