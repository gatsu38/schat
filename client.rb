require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'
require 'pry'
require 'pry-byebug'


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

    # obtain and validate keys
    puts "obtain kex"
    keys = receive_and_check(sock)
    # alice_box = RbNaCl::Box.new(bob_p, alice_s)
       
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
    binding.pry
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
