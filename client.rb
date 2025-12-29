require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'
require 'pry'
require 'pry-byebug'

# LIST OF FUNCTIONS
# server_identity_verification
  # !! verify server identity and connection genuinity !! add server pub key check
# hello_server method for client
  # initialize the connection with the server

PROTOCOL_NAME = "myproto-v1"
MAX_PROTO_FIELD = 30
MSG_CLIENT_HELLO_ID = "\x01"
MSG_SERVER_HELLO_ID = "\x02"
MSG_CLIENT_HELLO_ID2 = "\x03"
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
    opening_nonce = RbNaCl::Random.random_bytes(15)

    # create the opening message for client hello    
    opening_message = 
      protocol_start +
      MSG_CLIENT_HELLO_ID + 
      opening_nonce

    # send the first nonce to the server "client hello"
    puts "send opening nonce"
    write_all(sock, opening_message)

    # receive the signature and what's needed to verify it 
    puts "waiting for server signature"
    server_hello_back_payload = read_blob(sock, timeout: 10)
    # verify server identity and obtain keys + nonce
    server_info = peer_identity_verification(opening_nonce, protocol_start, server_hello_back_payload, "server", MSG_SERVER_HELLO_ID)

    # assign server's public key, ephemeral public key and signature
    server_pk = server_info[:remote_pk]
    server_eph_pk = server_info[:remote_eph_key]
    server_nonce = server_info[:remote_nonce]

    # create a signature only valid for these nonces
    signature = sig_builder(server_nonce, eph_pk, opening_nonce, "client", MSG_CLIENT_HELLO_ID2)

    # create the payload to be sent together with the signature in order
    # for the server to verify the client's authenticity
    hello_back_payload = hello_back_payload_builder(signature, eph_pk, opening_nonce, "client", MSG_CLIENT_HELLO_ID2)

    # send the hello back to the server, completing this way the hello protocol
    write_all(sock, hello_back_payload)
    client_box = RbNaCl::Box.new(server_eph_pk, eph_sk)
    {client_nonce: opening_nonce, server_nonce: server_nonce, client_box: client_box, server_eph_pk: server_eph_pk, server_pk: server_pk}

  end

  # ask the server if there's new messages 
  def check_messages
    
  end

  # inside the contact_list there must be a new contact option and the list of available chats
  # the existing contacts must have a unique check in case of a new message 
  def contact_list
    
  end

  def registration(sock)
    puts "Choose a nickname: "
    
    send_registration(sock, nickname, eph_pk, password, eph_pk_array)
  end

end

client = SecureClient.new("127.0.0.1", 2222)
print "Message: "
msg = STDIN.gets.strip
client.hello_server(msg)
