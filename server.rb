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

    # Send public signing key and ephemeral key (kex)
    send_kex(sock, @host_pk, eph_pk, sig)
    
    # Receive client ephemeral public key and stores it
    client_eph_pk = utils.read_blob(sock)

    # validate client's ephimeral key
    raise "Invalid client public key" unless client_public_key_check(client_eph_pk)

    # call function to create the key materials
    # obtain encription and mac keys from the key material
    key_material = key_material_func(client_eph_pk)
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


  # function to obtain the key_materials
  def key_material_func(client_eph_pk)
    # Shared secret derived from the server's private key (eph_sk) and 
    # the received client's pub key (clinet_eph_pk)
    shared_secret = eph_sk.exchange(client_eph_pk)

    # Let's make sure the derived shared key is safe (non zeros)
    if shared_secret == ("\x00" * 32)
      raise "Invalid or unsafe shared secret (all-zero) — abort"
    end

    # create a salt for the session
    session_salt = SecureRandom.random_bytes(16)

    # make info include the transcript to bind the keys
    transcript = "ssh-like" + eph_pk + client_eph_pk

    # 4) Derive keys, first create a 64 bytes long key material (km) then split it in half
    # obtain so the encription key and the mac_key 
    km = OpenSSL::KDF.hkdf(shared_secret, salt: session_salt, info: transcript, length: 64, hash: "SHA256")
  end


  # function to check the client_eph_pk (size, validity, non zeros)
  def client_public_key_check(raw_key)
  len = raw_key&.bytesize

  # X25519 public keys are always 32 bytes, guarantee size is correct
  # guarantee key is actually a valid key and also non zeros
  raise "Invalid public key length: #{len}" if len != RbNaCl::PublicKey::BYTES
  raise "Failed to read full public key" if client_eph_pk.nil? || raw_key.bytesize != len
  raise "Rejected all-zero public key" if raw_key == ("\x00" * 32)

  # create an object with the received bytes (client's ephimeral public key)
  # guarantees the key is a proper object and handled safely
  begin
    client_eph_pk = RbNaCl::PublicKey.new(raw_key)
  rescue RbNaCl::LengthError => e
    raise "Invalid public key: #{e.message}"
  end

  client_eph_pk
  end


  # this function is used to send the host public and ephemeral keys as well as the signature 
  def send_kex(sock, @host_pk, eph_pk, sig)

    # input validation
    raise ArgumentError, "Socket is nil" if sock.nil?
    raise ArgumentError, "Host public key is nil" if host_pk.nil?
    raise ArgumentError, "Ephemeral public key is nil" if eph_pk.nil?
    raise ArgumentError, "Signature is nil" if sig.nil?

    # send pub key and ephemeral key
    begin
      [@host_pk, eph_pk].each do |key|

        # check if the keys have the method to_bytes
        raise ArgumentError, "Invalid key object: #{key.inspect}" unless key.respond_to?(:to_bytes)

      bytes = key.to_bytes
      length = [bytes.bytesize].pack("N")
      utils.write_all(sock, length + bytes)
      end

    # send the signature of the ephemeral public key
    sig_length = [sig.bytesize].pack("N")
    utils.write_all(sock, sig_length + sig)

    # rescue clause 
    rescue IOError, Errno::EPIPE => e
      warn "Socket write failed: #{e.class} - #{e.message}"
      raise
    rescue StandardError => e
      warn "Unexpected error during send_keys: #{e.class} - #{e.message}"
      raise
    ensure 
      begin
	sock.close if sock && !sock.closed?
      rescue => close_error
	warn "Failed to close socket: #{close_error.class} - #{close_error.message}"
      end
    end
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
