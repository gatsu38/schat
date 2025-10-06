require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'

# used for error handling
class BlobSizeError < BlobReadError; end

# === Server ===
class SecureServer

# guarantee that the size sent is of max 16MB
MAX_BLOB_SIZE = 16 * 1024 * 1024


  # handles a single client 
  def handle_client(sock)
    # 1) Ephemeral X25519 server key
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    # 2) Sign ephemeral pub with host key, creates a signature
    sig = @host_sk.sign(eph_pk.to_bytes)

    # Send public signing key and ephemeral key 
    send_keys(sock, @host_pk, eph_pk, sig)
    
    # 3) Receive client ephemeral public key and stores it
    client_eph_pk = read_blob(sock)

    # validate client's ephimeral key
    unless client_public_key_check(client_eph_pk)
      raise "Invalid client public key"
    end

    # call function to create the key materials
    key_material = key_material_func(client_eph_pk)

    # obtain encription and mac keys from the key material
    enc_key = key_material[0,32]
    mac_key = key_material[32,32]


    # 5) Receive nonce, ciphertext, mac
    nonce = read_blob(sock)
    ciphertext = read_blob(sock)
    mac = read_blob(sock)

    # check if ciphertext has content
    if ciphertext.nil? || ciphertext.empty?
      raise "Invalid ciphertext: empty or nil"
    end

    # check mac size
    if mac.nil? || mac.bytesize != 32
      raise "Invalid MAC length: expected 32, got #{mac&.bytesize || 0}"
    end

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


  # function used to handle incoming data, timeout and size are handled here
  def read_blob(sock, MAX_BLOB_SIZE, timeout: 10)
    # read header (4 bytes), waits 10 seconds before giving up
    ready = IO.select([sock], nil, nil, timeout)
    raise Timeout::Error, "Timeout waiting for length header" unless ready

    # check header's size
    header = sock.read(4)
    raise EOFError, "Connection closed while reading length header" if header.nil? || header.bytesize < 4

    # sanity check for payload length
    blob_len = header.unpack1("N")  # unpack1 gives an integer directly
    raise BlobSizeError, "Invalid blob size: #{blob_len}" if blob_len < 0 || blob_len > max_blob_size

    # read payload (exactly blob_len bytes) blob will contain the payload
    # +"" creates a new mutable empty String (not frozen). 
    blob = +""
    while blob.bytesize < blob_len
      ready = IO.select([sock], nil, nil, timeout)
      raise Timeout::Error, "Timeout while reading blob" unless ready

      chunk = sock.read(blob_len - blob.bytesize)
      raise EOFError, "Connection closed while reading blob (expected #{blob_len}, got #{blob.bytesize})" if chunk.nil? || chunk.empty?

      blob << chunk
    end

    blob
  end
  
  
  # function to check the client_eph_pk (size, validity, non zeros)
  def client_public_key_check(raw_key)
  len = raw_key.bytesize

    # X25519 public keys are always 32 bytes, guarantee size is correct
    if len != RbNaCl::PublicKey::BYTES
      raise "Invalid public key length: #{len}"
    end

    # guarantee key is actually a valid key
    if client_eph_pk.nil? || raw_key.bytesize != len
      raise "Failed to read full public key"
    end

    # extra safety to avoid all zeroes public keys
    if raw_key == ("\x00" * 32)
      raise "Rejected all-zero public key"
    end

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
  def send_keys(sock, @host_pk, eph_pk, sig)

    # input validation
    raise ArgumentError, "Socket is nil" if sock.nil?
    raise ArgumentError, "Host public key is nil" if host_pk.nil?
    raise ArgumentError, "Ephemeral public key is nil" if eph_pk.nil?
    raise ArgumentError, "Signature is nil" if sig.nil?

    # send pub key and ephemeral key
    begin
      [@host_pk, eph_pk].each do |key|

        # check if the keys have the method to_bytes
        unless key.respond_to?(:to_bytes)
          raise ArgumentError, "Invalid key object: #{key.inspect}"
        end

      bytes = key.to_bytes
      length = [bytes.bytesize].pack("N")
      write_all(sock, length + bytes)
      end

    # send the signature of the ephemeral public key
    sig_length = [sig.bytesize].pack("N")
    write_all(sock, sig_length + sig)

    # rescue clause 
    rescue IOError, Errno::EPIPE => e
      warn "Socket write failed: #{e.message}"
      raise
    rescue StandardError => e
      warn "Unexpected error during send_keys: #{e.class} - #{e.message}"
      raise
    ensure 
      begin
	sock.close if sock && !sock.closed?
      rescue close_error
	warn "Failed to close socket: #{close_error.class} - #{close_error.message}"
      end
    end
  end


  # helper method to ensure full_write
  def write_all(sock, data)
    total_written = 0

    # tries to write as many bytes as possible and doesn't block the server
    while total_written < data.bytesize
      written = sock.write_nonblock(data[total_written..-1]
      total_written += written
    end

    # in case of failure wait untill the socket is writable, 5 maximum attempts
    rescue IO::WaitWritable
      ready = IO.select(nil, [sock], nil, 5)
      if ready.nil?
	raise IOError, "Socket not writable within timeout"
      else
        retry
      end
  end


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
    end
  end


end

SecureServer.new(2222).run
