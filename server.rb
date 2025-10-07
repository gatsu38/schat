require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'

# used for error handling
class BlobReadError < StandardError; end
class BlobSizeError < BlobReadError; end

# === Server ===
class SecureServer

  # handles a single client 
  def handle_client(sock)
    # Ephemeral X25519 server key pair, one pair per client
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    # Sign ephemeral pub with host key, creates a signature
    sig = @host_sk.sign(eph_pk.to_bytes)

    # create a salt for the session
    session_salt = SecureRandom.random_bytes(16)

    # Send public signing key and ephemeral key (kex)
    utils.send_kex(sock, @host_pk, eph_pk, sig, session_salt)
    
    # Receive host pub, server eph pub, signature
    keys = utils.receive_and_check()
    client_pk = keys[:public_key]
    client_eph_pk = keys[:ephemeral_key]

    # call function to create the key materials
    # obtain encription and mac keys from the key material
    key_material = utils.key_material_func(eph_sk, eph_pk, client_eph_pk, salt)
    enc_key = key_material[0,32]
    mac_key = key_material[32,32]

    # Receive nonce, ciphertext, mac and check for proper size/content value
    nonce = utils.read_blob(sock)
    ciphertext = utils.read_blob(sock)
    mac = utils.read_blob(sock)
    check_nonce_ciph

    raise "Invalid nonce length: expected 12 bytes, got #{nonce&.bytesize || 0}" unless nonce&.bytesize == 12
    raise "Invalid ciphertext: empty or nil" if ciphertext.nil? || ciphertext.empty?
    raise "Invalid MAC length: expected 32, got #{mac&.bytesize || 0}" if mac.nil? || mac.bytesize != 32

    # Verify HMAC
    hmac = OpenSSL::HMAC.digest("SHA256", mac_key, nonce + ciphertext)
    if hmac != mac
      puts "HMAC failed!"
      sock.close
      return
    end

    # Decrypt AES-CTR
    # create a new cipher object
    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    # sets cipher to decryption mode
    cipher.decrypt
    # set decryption key
    cipher.key = enc_key
    # set initialization vector to nonce
    cipher.iv = nonce
    # obtain fully decrypted text
    plaintext = cipher.update(ciphertext) + cipher.final

    puts "Received: #{plaintext}"
    sock.write("OK")
    sock.close
  end


  # create a Ed25519 private key (signing key)
  # used to sign the server's ephimeral public key
  # @host_pk contains the derived public key
  # !!!!!!!! this part has to be changed for proper host key handling !!!!!!!!
  # !!!!!!!! TO FIX !!!!!!!!!
  def initialize(port)
    @port = port

    # Long-term host key (Ed25519)
    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
    @host_pk = @host_sk.verify_key
  end  


  # handles the incoming connections 
  # spawns a new thread for each new client connection
  def run
    server = TCPServer.open(@port)
      puts "Server listening on port #{@port}"
      loop do
        client = server.accept
        Thread.new(client) do |c|
	  begin
	    handle_client(c)
	  rescue StandardError => e 
	    # send error message to che client
	    begin
	      c.write "connection failed: #{e.message}"
	    rescue send_error
	      puts "failed to send error to the client: #{send_error.message}"
	    end
	    puts "Thread exception #{e.class} - #{e.message}"
	  ensure
	    c.close 
	  end
	end
      end
  ensure
    server.close if server
  end


end

SecureServer.new(2222).run
