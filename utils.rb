# reading and writing functions
# as well as checks
module Utils

MAX_BLOB_SIZE = 16 * 1024 * 1024

  # function to receive public key, ephimeral key and signature
  def receive_and_check(sock)
    public_key = read_blob(sock)
    puts "public_key received"
    ephemeral_key = read_blob(sock)
    puts "ephemeral_key received"
    signature = read_blob(sock)
    puts "signature received"
    salt = read_blob(sock)
    puts "salt received"

    # validate server's public_key, ephimeral key, signature and salt
    result = handshake_check(public_key, ephemeral_key, signature, salt)
  end 


  # function to obtain the full content of the socket
  def read_blob(sock, timeout: 1000)
    # read header (4 bytes), waits 10 seconds before giving up
    ready = IO.select([sock], nil, nil, timeout)
    raise Timeout::Error, "Timeout waiting for length header" unless ready

    # check header's size
    header = sock.read(4)
    raise EOFError, "Connection closed while reading length header" if header.nil? || header.bytesize < 4

    # sanity check for payload length
    blob_len = header.unpack1("N")  # unpack1 gives an integer directly
    raise BlobSizeError, "Invalid blob size: #{blob_len}" if blob_len < 0 || blob_len > MAX_BLOB_SIZE

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


  # helper method to ensure full_write on the remote socket
  def write_all(sock, data)
    total_written = 0
    attempts = 0 
    begin
      # tries to write as many bytes as possible and doesn't block the server
      while total_written < data.bytesize
        written = sock.write_nonblock(data[total_written..-1])
        total_written += written
      end

    # in case of failure wait untill the socket is writable, 5 maximum attempts
    rescue IO::WaitWritable
      attempts += 1
      raise IOError, "Socket not writable after 5 attempts" if attempts >= 5
      ready = IO.select(nil, [sock], nil, 5)
      retry if ready 
      raise IOError, "Socket not writable within timeout"
      
    end
  end


  # function to check the client_eph_pk (size, validity, non zeros)
  def key_format_check(raw_key)
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

  # this function is used to send the public and ephemeral keys as well as the signature 
  def send_kex(sock, host_pk, eph_pk, sig, salt)

    # input validation
    raise ArgumentError, "Socket is nil" if sock.nil?
    raise ArgumentError, "Host public key is nil" if host_pk.nil?
    raise ArgumentError, "Ephemeral public key is nil" if eph_pk.nil?
    raise ArgumentError, "Signature is nil" if sig.nil?

    # send pub key and ephemeral key
    # !!! possibly make it shorter inserting sig and salt in the block
    begin
      [host_pk, eph_pk].each do |key|

        # check if the keys have the method to_bytes
        raise ArgumentError, "Invalid key object: #{key.inspect}" unless key.respond_to?(:to_bytes)

      bytes = key.to_bytes
      length = [bytes.bytesize].pack("N")
      write_all(sock, length + bytes)
      end

    # send the signature of the ephemeral public key
    sig_length = [sig.bytesize].pack("N")
    write_all(sock, sig_length + sig)

    salt_length = [salt.bytesize].pack("N")
    write_all(sock, salt_length + salt)

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


  # function to check the validity of the keys and signature
  def handshake_check(pb_key, eph_key, sig, salt)
    begin
      # 1. Validate and construct server public key
      pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(pb_key)
    rescue RbNaCl::LengthError, RbNaCl::CryptoError => e
      raise "Invalid server public key: #{e.message}"
    end

    begin
      # 2. Validate and construct ephemeral public key
      eph_pk = RbNaCl::PublicKey.new(eph_key)
    rescue RbNaCl::LengthError, RbNaCl::CryptoError => e
      raise "Invalid server ephemeral public key: #{e.message}"
    end

    begin
      # 3. Verify signature (server proves it owns the public key)
      # The signature must be valid for eph_pk.to_bytes using server_pk
      pk.verify(sig, eph_pk.to_bytes)
    rescue RbNaCl::BadSignatureError
      raise "Invalid signature: does not match the server public key"
    end

    begin
      # check the salt's validity
      raise "Missing salt" if salt.nil?
      raise "Invalid salt length: #{salt.bytesize}" unless salt.bytesize == 16
      raise "Salt is all zeros" if salt == ("\x00" * 16)
      raise "Low-entropy salt (repeated byte)" if salt.each_byte.uniq.length == 1

    rescue => e
      raise "Salt verification failed: #{e.message}"
    end
    
    { public_key: pk, ephemeral_key: eph_pk, sig: sig, salt: salt }
  end


  # function to obtain the key_materials
  def key_material_func(local_eph_sk, local_eph_pk, remote_eph_pk, salt)
    # Shared secret derived from the server's private key (eph_sk) and 
    # the received client's ephemeral pub key (remote_eph_pk)
    shared_secret = RbNaCl::Box.new(remote_eph_pk, local_eph_sk).key

    # Let's make sure the derived shared key is safe (non zeros)
    raise "Invalid or unsafe shared secret (all-zero) — abort" if shared_secret == ("\x00" * 32)

    # make info include the transcript to bind the keys
    transcript = "ssh-like" + local_eph_pk + remote_eph_pk

    # 4) Derive keys, first create a 64 bytes long key material (km) then split it in half
    # obtain so the encription key and the mac_key 
    km = OpenSSL::KDF.hkdf(shared_secret, salt: salt, info: transcript, length: 64, hash: "SHA256")
  end


end
