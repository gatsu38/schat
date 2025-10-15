#!/usr/bin/env ruby
require 'sqlite3'
require 'rbnacl'

# !!!! FIXARE IL PATH
DB_FILE = File.expand_path('~/schat.db')
CONTACTS_TABLE = 'contacts'
USER_TABLE = 'user'
KEYS_TABLE = 'ephemeral_keys'


if File.exist?(DB_FILE)
  puts "Database already exists. Would you like to create a new identity? Y/N"
  answer = gets.chomp.stip.upcase
  exit unless answer == 'Y'
end

begin

db = SQLite3::Database.new(DB_FILE)

# create a table for the current user info
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{USER_TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL CHECK (
      length(username) <= 20 AND
      username GLOB '[A-Za-z0-9]*'
    ),
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP  
  );
SQL

# create a table for the contacts info
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{CONTACTS_TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE CHECK (
      length(username) <= 20 AND 
      username GLOB '[A-Za-z0-9]*'
    ),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL

# createa table to keep track of the ephemeral public keys shared 
db.execute <<-SQL
  CREATE TABLE IF NOT EXISTS #{KEYS_TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ephemeral_private_key BLOB NOT NULL CHECK (length(ephemeral_private_key) = 32),
    ephemeral_public_key BLOB NOT NULL CHECK (length(ephemeral_public_key) = 32),
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
SQL

rescue SQLite3::Exception => e
  puts "❌ Database error: #{e.message}"
ensure
  #db.close if db
end

puts "table #{USER_TABLE} ready"

new_identity(db)
db.close

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
    "INSERT INTO #{USER_TABLE} (username, private_key, public_key) VALUES (?, ?, ?)
    [username, host_sk.to_bytes, host_pk.to_bytes]
  )  
  puts "New identity created successfully"
end

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
