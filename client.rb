require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'
require 'pry'
require 'pry-byebug'
require 'sqlite3'

# LIST OF FUNCTIONS
# server_identity_verification
  # !! verify server identity and connection genuinity !! add server pub key check
# hello_server method for client
  # initialize the connection with the server
# registration
  # send registration request with nickname and voucher
# registration_builder
  # build the registration package
  
DB_FILE = "/home/kali/schat_db/client.db"
PROTOCOL_NAME = "myproto-v1"
MAX_PROTO_FIELD = 30
MSG_CLIENT_HELLO_ID = "\x01"
MSG_SERVER_HELLO_ID = "\x02"
MSG_CLIENT_HELLO_ID2 = "\x03"
MSG_CLIENT_REGISTRATION = "\x04"
MSG_SERVER_REGISTRATION_CONFIRMED = "\x05"
class ProtocolError < StandardError; end

class SecureClient

  include Utils

  def initialize(host, port)
    @host, @port = host, port

    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
    @host_pk = @host_sk.verify_key
  end


  # main method
  def hello_server(msg)
    
    # Ephemeral client key
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key
  
    puts "created: ephemeral private key, public key and signature"

    # establish a connection with the server
    sock = TCPSocket.new(@host, @port)
    puts "TCP connection established"

    # protocol name + padding preparation
    protocol_start = protocol_name_builder(PROTOCOL_NAME, MAX_PROTO_FIELD)

    # create the nonce used to validate the session
    client_nonce = RbNaCl::Random.random_bytes(15)

    # create the opening message for client hello    
    opening_message = 
      protocol_start +
      MSG_CLIENT_HELLO_ID + 
      client_nonce

    # send the first nonce to the server "client hello"
    puts "send opening nonce"  
    write_all(sock, opening_message)

    # receive the signature and what's needed to verify it 
    puts "waiting for server signature"
    server_hello_back_payload = read_blob(sock)
    # verify server identity and obtain keys + nonce
    server_info = peer_identity_verification(client_nonce, protocol_start, server_hello_back_payload, "server", MSG_SERVER_HELLO_ID)
    # assign server's public key, ephemeral public key and signature
    server_pk = server_info[:remote_pk]
    server_eph_pk = server_info[:remote_eph_pk]
    server_nonce = server_info[:remote_nonce]

    # create a signature only valid for these nonces
    signature = sig_builder(server_nonce, eph_pk, client_nonce, "client", MSG_CLIENT_HELLO_ID2)

    # create the payload to be sent together with the signature in order
    # for the server to verify the client's authenticity
    hello_back_payload = hello_back_payload_builder(signature, eph_pk, client_nonce, "client", MSG_CLIENT_HELLO_ID2)

    # send the hello back to the server, completing this way the hello protocol
    write_all(sock, hello_back_payload)
    client_box = RbNaCl::Box.new(server_eph_pk, eph_sk)
    {client_nonce: client_nonce, server_nonce: server_nonce, client_box: client_box, server_eph_pk: server_eph_pk, server_pk: server_pk, sock: sock}
  end

  # ask the server if there's new messages 
  def check_messages
    
  end

  # inside the contact_list there must be a new contact option and the list of available chats
  # the existing contacts must have a unique check in case of a new message 
  def contact_list
        
  end

  def registration_confirmation()

  end

  # ask the user to provide a valid voucher and also recover the nickname from the db
  def registration(handshake_info, nonce_session)
    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    nickname = db.get_first_value(<<-SQL)
      SELECT username FROM user;
    SQL

    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]
    
    puts "Insert a valid voucher:"
    voucher = STDIN.gets.strip

    registration_data = registration_builder(nickname, voucher)

    returned_confirmation = sender(handshake_info[:sock], handshake_info[:client_box], nonce_session, registration_data)

    confirmation = registration_confirmation(returned_confirmation)
    
    if confirmation == true
      puts "Registration successful"
    else
      puts "Registration failed"
    end

  end

  # build the registration message
  def registration_builder(nickname, voucher)
    raise ArgumentError, "Nickname too long" if nickname.bytesize > 20

    registration_payload = 
      MSG_CLIENT_REGISTRATION +
      [nickname.bytesize].pack("C") +
      nickname +
      voucher

    registration_payload      
  end

  # this method is used to cip
  
  

  # used to generate, check and update the ephemeral_keys 
  def ephemeral_keys_update(handshake_info)
    
  end

end

def main
include Utils
  puts "Schat. SecureChat client v1.0"
  puts "Choose an option:"
  puts "1) Register"
  puts "2) Check contact list"
  puts "3) Send message"
  puts "4) Get messages"
  choice = STDIN.gets.strip
  client = SecureClient.new("127.0.0.1", 2222)
  
  # inside handshake info there is all the info concerning the connection:
  # keys, nonces, box and socket
  handshake_info = client.hello_server(choice)

  # create and get the nonce ready
  nonce_session = Session.new("server", handshake_info[:client_nonce])

  client.registration(handshake_info, nonce_session)

  new_nonce = nonce_session.next_nonce
  
  client.ephemeral_keys_update(handshake_info)
end
main
