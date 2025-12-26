require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'
require 'pry'
require 'pry-byebug'

PROTOCOL_NAME = "myproto-v1"
MAX_PROTO_FIELD = 30
MSG_CLIENT_HELLO_ID = "\x01"
MSG_SERVER_HELLO_ID = "\x02"

class ProtocolError < StandardError; end

class SecureClient

  include Utils

  def initialize(host, port)
    @host, @port = host, port

    @client_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
    @client_pk = @client_sk.verify_key
  end


  # verify server identity and connection genuinity
  def server_identity_verification(opening_nonce, payload)
    offset = 0

    # protocol name
    proto = read_exact(payload, offset, 30)
    offset += 30
    raise "protocol mismatch" unless proto == PROTOCOL_NAME

    # message ID
    msg_id = read_exact(payload, offset, 1)
    offset += 1
    raise "Unexpected message type" unless msg_id == MSG_SERVER_HELLO_ID.ord

    # role of the sender
    role = read_exact(payload, offset, "server".bytesize)
    offset += "server".bytesize
    raise "Invalid sender role" unless role == "server"
    
    # server public key
    server_pk_bytes = read_exact(payload, offset, 32)
    offset += 32
    # check quality of the key
    begin
      server_pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(server_pk_bytes)
    rescue RbNaCl::CryptoError
      raise ProtocolError, "Invalid Server public key"
    end
    # !!!! TO BE ADD
    # raise "Untrusted server key" unless server_pk_bytes == @trusted_server_pk

    # server eph pk
    server_eph_pk_bytes = read_exact(payload, offset, 32)
    offset += 32
    begin
      server_eph_pk = RbNaCl::PublicKey.new(server_eph_pk_bytes)
    rescue RbNaCl::CryptoError
      raise ProtocolError, "Invalid server ephemeral public key"
    end
    
    # server nonce
    server_nonce = read_exact(payload, offset, RbNaCl::Box.nonce_bytes)
    offset += RbNaCl::Box.nonce_bytes

    # check if the nonce is non zero
    if server_nonce.bytes.all? { |b| b == 0 }
      raise ProtocolError, "Invalid server nonce (all-zero)"
    end

    # signature
    signature = read_exact(payload, offset, 64)
    offset += 64
    raise "Trailing bytes detected" unless offset == payload.bytesize

    # rebuild transcript
    transcript = 
      [PROTOCOL_NAME.bytesize].pack("n") +
      [PROTOCOL_NAME] +
      MSG_SERVER_HELLO_ID +
      "server" +
      server_pk_bytes +
      opening_nonce +
      server_nonce +
      server_eph_pk_bytes

    # signature verification
    unless server_pk.verify(signature, transcript)
      raise "Server signature verification failed"
    end

    {server_pk: server_pk, server_eph_pk: server_eph_pk, server_nonce: server_nonce}
  end
  
  # initialize the connection with the server
  def initialization(msg)
    
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
    opening_nonce = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)

    # create the opening message for client hello    
    opening_message = 
      protocol_start +
      MSG_CLIENT_HELLO_ID + 
      opening_nonce

    binding.pry
    
    # send the first nonce to the server
    puts "send opening nonce"
    write_all(sock, opening_message, true)

    binding.pry

    # receive the signature and what's needed to verify it
    puts "waiting for server signature"
    hello_back_payload = read_blob(sock)

    # verify server identity
    server_identity_verification(opening_nonce, hello_back_payload)

    # receive kex
    puts "receive kex"        
    keys = receive_and_check(sock)
       
    # Receive server's public key, ephemeral public key and signature
    server_pk = keys[:public_key]
    server_eph_pk = keys[:ephemeral_key]
    nonce = keys[:nonce]
    server_sig = keys[:sig]
    puts "kex received"

    # Send public signing key and ephemeral key (kex)
    puts "sending kex"
    send_kex(sock, @client_pk, eph_pk, sig, nonce)
    client_box = RbNaCl::Box.new(server_eph_pk, eph_sk)
    ciphertext = client_box.encrypt(nonce, msg)
    write_all(sock, ciphertext)
    puts "hi"        

    sock.close
  end

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
client.initialization(msg)
