require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require 'timeout'

# === Server ===
class SecureServer

# guarantee that the size sent is of max 16MB
MAX_BLOB_SIZE = 16 * 1024 * 1024

  # create a Ed25519 private key (signing key)
  # used to sign the server's ephimeral public key
  # @host_pk contains the derived public key
  def initialize(port)
    @port = port

    # Long-term host key (Ed25519)
    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
    @host_pk = @host_sk.verify_key
  end

  # handles the incoming connections 
  # spawns a new thread for each new client connection
  def run
    TCPServer.open(@port) do |server|
      puts "Server listening on port #{@port}"
      loop do
        client = server.accept
        Thread.new { handle_client(client) }
      end
    end
  end

  # handles a single client 
  def handle_client(sock)
    # 1) Ephemeral X25519 server key
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    # 2) Sign ephemeral pub with host key, creates a signature
    sig = @host_sk.sign(eph_pk.to_bytes)

    # Send public signing key and ephemeral key 
    begin
      [@host_pk, eph_pk].each do |key|
      bytes = key.to_bytes
      length = [bytes.bytesize].pack("N")
      sock.write(length + bytes)
    end

    # send the signature of the ephemeral public key
    sig_length = [sig.bytesize].pack("N")
    sock.write(sig_length + sig)

    # rescue clause 
    rescue IOError, Errno::EPIPE => e
      puts "Socket write failed: #{e.message}"
      sock.close rescue nil
    rescue => e
      puts "Unexpected error during socket write: #{e.class} - #{e.message}"
      sock.close rescue nil
    end


    # 3) Receive client ephemeral public key and stores it
    len_buf = sock.read(4)
    raise "Connection closed" unless len_buf
    len = len_buf.unpack1("N")

    # X25519 public keys are always 32 bytes, guarantee size is correct
    if len != RbNaCl::PublicKey::BYTES
      raise "Invalid public key length: #{len}"
    end

    # guarantee key is actually ket
    raw_key = sock.read(len)
    if raw_key.nil? || raw_key.bytesize != len
      raise "Failed to read full public key"
    end

    # extra safety to avoid all zeroes public keys
    if raw_key == ("\x00" * 32)
      raise "Rejected all-zero public key"
    end

    # create a object with the received bytes (ephimeral public key)
    # guarantees the key is in a proper object and handled safely
    begin
      client_eph_pk = RbNaCl::PublicKey.new(raw_key)
    rescue RbNaCl::LengthError => e
      raise "Invalid public key: #{e.message}"
    end

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
    enc_key = km[0,32]
    mac_key = km[32,32]


    # 5) Receive nonce, ciphertext, mac
    nonce = read_blob(sock)
    ciphertext = read_blob(sock)
    mac = read_blob(sock)

    # Verify HMAC
    hmac = OpenSSL::HMAC.digest("SHA256", mac_key, nonce + ciphertext)
    if hmac != mac
      puts "HMAC failed!"
      sock.close
      return
    end

    # Decrypt AES-CTR
    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.decrypt
    cipher.key = enc_key
    cipher.iv  = nonce
    plaintext = cipher.update(ciphertext) + cipher.final

    puts "Received: #{plaintext}"
    sock.write("OK")
    sock.close
  end


  # function for raw reading of the socket
  def read_blob(sock)
    len = sock.read(4).unpack1("N")
    sock.read(len)
  end
end

SecureServer.new(2222).run
