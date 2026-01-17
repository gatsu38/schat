#!/usr/bin/env ruby
require 'sqlite3'
require 'rbnacl'
require 'pry'
require 'pry-byebug'
# !!!! FIX PATH
DB_FILE = File.expand_path('/home/kali/schat_db/client.db')
CONTACTS_TABLE = 'contacts'
USER_TABLE = 'user'
KEYS_TABLE = 'ephemeral_keys'
SERVER_IDENTITY = 'server_identity'
SHARED_PREKEY = 'shared_prekey'
ONE_TIME_KEYS = 'one_time_prekeys'
CLIENTS_INFO = 'clients_info'
if File.exist?(DB_FILE)
  puts "Database already exists. Would you like to create a new identity? Y/N"
  answer = gets.chomp.strip.upcase
  exit unless answer == 'Y'
end

begin

binding.pry

  db = SQLite3::Database.new(DB_FILE)


  # create a table for the current user info
  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS #{USER_TABLE} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL CHECK (
        length(username) <= 20 AND
        username GLOB '[A-Za-z0-9]*'
      ),
      private_key BLOB NOT NULL CHECK (length(private_key) = 32),
      public_key BLOB NOT NULL CHECK (length(public_key) = 32),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP  
    );
  SQL


  db.execute <<-SQL
    CREATE TABLE clients_info (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE CHECK (
        length(username) BETWEEN 1 AND 20 AND
        username NOT GLOB '*[^A-Za-z0-9]*'
      ),
      public_key BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32),
      signed_prekey_pub BLOB UNIQUE CHECK (signed_prekey_pub IS NULL OR length(signed_prekey_pub) = 32),
      signed_prekey_sig BLOB UNIQUE CHECK (signed_prekey_sig IS NULL OR length(signed_prekey_sig) = 64),
      one_time_key BLOB UNIQUE CHECK (one_time_key IS NULL OR length(one_time_key) = 32),
      spk_created_at TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  SQL


  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS #{SERVER_IDENTITY} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_name TEXT UNIQUE,
      public_key BLOB NOT NULL CHECK (length(public_key) = 32),
      fingerprint TEXT NOT NULL,
      added_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  SQL


  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS #{SHARED_PREKEY} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      private_signed_prekey BLOB NOT NULL CHECK (length(private_signed_prekey) = 32),
      public_signed_prekey BLOB NOT NULL CHECK (length(public_signed_prekey) = 32),
      addet_at DATETIME DEFAULT CURRENT_TIMESTAMP      
    );
  SQL


  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS #{ONE_TIME_KEYS} (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      one_time_public_key BLOB NOT NULL CHECK (length(one_time_public_key) = 32),
      one_time_private_key BLOB NOT NULL CHECK (length(one_time_private_key) = 32),
      counter INTEGER NOT NULL
    );
  SQL

  rescue SQLite3::Exception => e
    puts "❌ Database error: #{e.message}"
  ensure
end

puts "table #{USER_TABLE} ready"


def new_identity(db)
  puts "Enter username (5-20 chars, lowercase, uppercase 0-9 only)"
  username = nil
  loop do
    username = gets.chomp
    if username.match?(/\A[A-Za-z0-9]{5,20}\z/)
      break
    else
      puts "Invalid username, retry: "
    end
  end

  host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
  host_pk = host_sk.verify_key

  db.execute(
    "INSERT INTO #{USER_TABLE} (username, private_key, public_key) VALUES (?, ?, ?)", [username, host_sk.to_bytes, host_pk.to_bytes]
  );  
  puts "New identity created successfully"
end

new_identity(db)
db.close

# !!!!! INSERT PROTECTION FOR THE PRIVATE KEY 
# insert private and public key inside the database
# protect database with user password
# !!!!! ADD EXTRA PROTECTION IN THIS PHASE????
# !!!!! ADD PASSWORD MINIMUM SECURITY

# ------------------------------------------

# puts "enter password to protect the database"
# user_password = STDIN.noecho(&:gets).chomp

# !!!!! ADD PROTECTION
# password_key = Digest::SHA256.digest(user_password)

# tpm_key = tpm_function

# master_key_bytes = password_key.bytes.zip(tpm_key.bytes).map { |a,b| (a ^ b).chr }.join
# mater_key = RbNaCl::SecretBox.new(master_key_bytes)
