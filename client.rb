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
    sig = @client_sk.sign(eph_pk.to_bytes)

    puts "created: ephemeral private key, public key and signature"

    # establish a connection with the server
    sock = TCPSocket.new(@host, @port)
    puts "TCP connection established"

    # obtain and validate keys
    puts "obtain kex"
    keys = receive_and_check(sock)
   
    # Receive server's public key, ephemeral public key and signature
    server_pk = keys[:public_key]
    server_eph_pk = keys[:ephemeral_key]
    salt = keys[:salt]
    server_sig = keys[:sig]
    binding.pry
    puts "kex received"

    # Send public signing key and ephemeral key (kex)
    puts "sending kex"
    send_kex(sock, @client_pk, eph_pk, sig, salt)
    # confirm kex has been sent
    # confirm_kex_arrived(sock, server_sig)
    
    puts "kex sent"
    # 4) Derive keys
    key_material = key_material_func(eph_sk, eph_pk, server_eph_pk, salt) 
    enc_key = key_material[0,32]
    mac_key = key_material[32,32]

    # 5) Encrypt
    nonce = SecureRandom.random_bytes(16)
    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.encrypt
    cipher.key = enc_key
    cipher.iv  = nonce
    ciphertext = cipher.update(msg) + cipher.final

    mac = OpenSSL::HMAC.digest("SHA256", mac_key, nonce + ciphertext)

    # 6) Send client eph pub, nonce, ciphertext, mac
    send_blob(sock, eph_pk.to_bytes)
    send_blob(sock, nonce)
    send_blob(sock, ciphertext)
    send_blob(sock, mac)

    puts "Server says: #{sock.read}"
    sock.close
  end


  def send_blob(sock, data)
    sock.write([data.bytesize].pack("N") + data)
  end
end

client = SecureClient.new("127.0.0.1", 2222)
print "Message: "
msg = STDIN.gets.strip
client.send_message(msg)
