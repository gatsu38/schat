require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'
require 'pry'
require 'pry-byebug'

PROTOCOL_ID = "myproto-v1"
MSG_CLIENT_HELLO = "\x01"

class SecureClient

  include Utils

  def initialize(host, port)
    @host, @port = host, port

    @client_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
    @client_pk = @client_sk.verify_key
  end

  def send_message(msg)
    
    # Ephemeral client key
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    # Sign ephemeral pub with host key, creates a signature
    sig = @client_sk.sign(eph_pk.to_s)

    puts "created: ephemeral private key, public key and signature"

    # establish a connection with the server
    sock = TCPSocket.new(@host, @port)
    puts "TCP connection established"


    opening_nonce = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
    opening_message = [PROTOCOL_ID.bytesize].pack("N") + PROTOCOL_ID + MSG_CLIENT_HELLO + opening_nonce
    
    # send the first nonce to the server
    begin
      write_all(sock, opening_message)
      binding.pry
    rescue IOError => e
      log("Connection failed: #{e.message}")
      exit
    end    

    # receive the signature and what's needed to verify it
    hello_back_payload = read_blob(sock)

    # verify server identity
    server_verification(hello_back_payload)

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
client.send_message(msg)
