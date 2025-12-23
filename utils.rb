# reading and writing functions
# as well as checks

#LIST OF FUNCTIONS:
# write_all           (checked) 
# read_blob           (checked)
# blob_confirmation   (checked)
# confirm_kex_arrived (checked)
# kex_parser          (checked)
# handshake_check     (checked)

require 'timeout'
require 'rbnacl'
module Utils

MAX_BLOB_SIZE = 16 * 1024 * 1024
MAX_FIELD_SIZE = 1024

  def receive_nonce(sock)
    blob = read_blob(sock)
    offset = 0

    # 1) Read protocol ID length (4 bytes)
    raise IOError, "Blob too short for protocol length" if blob.bytesize < 4
    proto_len = blob.unpack1("N")
    offset += 4

    # 2) Read protocol ID
    raise IOError, "Blob too short for protocol ID" if blob.bytesize < offset + proto_len
    protocol_id = blob.byteslice(offset, proto_len)
    offset += proto_len

    unless protocol_id == PROTOCOL_ID
      raise IOError, "Protocol mismatch: #{protocol_id.inspect}"
    end

    # 3) Read message type (1 byte)
    raise IOError, "Blob too short for message type" if blob.bytesize < offset + 1
    msg_type = blob.getbyte(offset)
    offset += 1

    unless msg_type == MSG_CLIENT_HELLO.getbyte(0)
      raise IOError, "Unexpected message type: #{msg_type}"
    end

    # 4) Remaining bytes are the nonce
    nonce = blob.byteslice(offset, blob.bytesize - offset)

    # Optional sanity check
    unless nonce.bytesize == RbNaCl::Box.nonce_bytes
      raise IOError, "Invalid nonce size: #{nonce.bytesize}"
    end
    nonce
  end


  # function to receive public key, ephimeral key and signature
  def receive_and_check(sock)
    raise ArgumentError, "Socket is nil" if sock.nil?
    
    returned_blob = read_blob(sock)

    # send back hash of blob
    blob_confirmation(sock, returned_blob)

    # parse the blob into 4 different contents 
    keys = kex_parser(returned_blob)
    rescue IOError, Errno::EPIPE => e
      warn "Socket read failed: #{e.class} - #e.message}"
      raise
    rescue StandardError => e
      warn "Unexpected error during read_kex: #{e.class} - #{e.message}"
      raise  
  end 


  # send back a hash of the blob (kex) to confirm arrival of kex
  def blob_confirmation(sock, blob)
    digest = RbNaCl::Hash.sha256(blob)
    write_all(sock, digest)
  end
  

  # parse the blob to obtain the kex
  def kex_parser(blob)
    # keys = [:public_key, :ephemeral_pub_key, :sig, :salt]
    result = []
    pos = 0 
    4.times do 

      # raise error if the length header exceeds the size of the blob
      raise IOError, "Truncated blob (missing length for field #{i})" if pos + 4 > blob_size
      len = blob.byteslice(pos, 4).unpack1('N')
      pos += 4
      # raise error if the field is unreasonably large
      raise IOError, "Field #{i} too large (#{len} bytes)" if len > MAX_FIELD_SIZE
      # raise error if the blob is smaller than the declared size
      raise IOError, "Truncated blob (field #{i})" if pos + len > blob_size
      payload = blob.byteslice(pos, len)
      pos += len
      # raise error if payload is nil or incongruency between payload actual size and declared size
      raise IOError, "Invalid payload for field #{i}" if payload.nil? || payload.bytesize != len
      result << payload  
    end
    kex = handshake_check(result[0], result[1], result[2], result[3]) 
  end


  # function to check the validity of the keys and signature
  def handshake_check(pb_key, eph_key, sig, nonce)
    begin
      # 1. Validate and construct server public key
      pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(pb_key)
      #pk = OpenSSL::PKey::Ed25519.new(pb_key)
    rescue RbNaCl::LengthError, RbNaCl::CryptoError => e
      raise "Invalid server public key: #{e.message}"
    end

    begin
      # 2. Validate and construct ephemeral public key
      eph_pk = RbNaCl::PublicKey.new(eph_key)
      #eph_pk = OpenSSL::PKey::X25519.new(eph_key)
    rescue RbNaCl::LengthError, RbNaCl::CryptoError => e
      raise "Invalid server ephemeral public key: #{e.message}"
    end

    begin
      # 3. Verify signature (server proves it owns the public key)
      # The signature must be valid for eph_pk using the remote pk      
      pk.verify(sig, eph_pk.to_bytes)
    rescue RbNaCl::BadSignatureError
      raise "Invalid signature: does not match the server public key"
    end

    begin
      # check the nonce's validity
      raise "Missing nonce" if nonce.nil?
      raise "Invalid nonce length: #{nonce.bytesize}" unless nonce.bytesize == 24
      raise "Nonce is all zeros" if nonce == ("\x00" * 24)
      raise "Low-entropy nonce (repeated byte)" if nonce.each_byte.uniq.length == 1

    rescue => e
      raise "Nonce verification failed: #{e.message}"
    end

    { public_key: pk, ephemeral_key: eph_pk, sig: sig, nonce: nonce }
  end


  # this function is used to send the public and ephemeral keys as well as the signature 
  def send_kex(sock, *blobs)

    # check sock not nil
    raise ArgumentError, "Socket is nil" if sock.nil?
    begin

      # check blob content not nil
      raise ArgumentError, "Kex argument missing" if blobs.nil?

      # build a big payload made of all the content needed for kex
      payload = blobs.flat_map do |blob|
        data = blob.respond_to?(:to_bytes) ? blob.to_bytes : blob
        [ [data.bytesize].pack("N"), data]
      end.join

      # create a digest of the whole payload less the total size header
      digest = RbNaCl::Hash.sha256(payload)

      # send the full_payload        
      write_all(sock, payload)
      confirm_kex_arrived(sock, digest)


    # rescue clause 
    rescue IOError, Errno::EPIPE => e
      warn "Socket write failed: #{e.class} - #{e.message}"
      raise
    rescue StandardError => e
      warn "Unexpected error during send_keys: #{e.class} - #{e.message}"
      raise
    end
  end

  # obtain a hash of the blob (kex) and confirm it arrived
  def confirm_kex_arrived(sock, digest)
    confirmation = read_blob(sock)
      if confirmation == digest

        puts "Kex sent and received"
        return true
      else
        puts "Kex receival non confirmed"
        raise "Kex receival non confirmed"
      end
  end
 


  # function to obtain the full content of the socket
  def read_blob(sock, timeout: 10, max_attempts:5)
    attempts = 0
    
    begin
      attempts += 1
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

      # make sure the full blob has been sent with the exact size
      unless header.unpack1("N") == blob.size
        raise IOError, "blob length mismatch: expected size: #{header.unpack1("N")}, obtained: #{blob.size}"
      end

      blob

    rescue Timeout::Error, EOFError, BlobSizeError => e
      if attempts < max_attempts
        puts "Attempt #{attempts} failed: #{e.message}. Retrying..."
        retry
      else
        puts "All #{max_attempts} attempts failed."
        raise
      end
    end
  end


  # helper method to ensure full_write on the remote socket
  def write_all(sock, payload)

    # prefix the payload with the whole size of the payload
    total_length = payload.bytesize
    header = [total_length].pack("N")
    data = header + payload
  
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
        if attempts >= 5
          sock.close
          abort IOError, "Socket not writable after 5 attempts. Sock closed. Schat closed" 
        end  
      ready = IO.select(nil, [sock], nil, 5)
      retry if ready 
      raise IOError, "Socket not writable within timeout"
      
    end
  end


  # function to obtain the key_materials
  #def key_material_func(local_eph_sk, local_eph_pk, remote_eph_pk, salt)
    # Shared secret derived from the server's private key (eph_sk) and 
    # the received client's ephemeral pub key (remote_eph_pk)
    # shared_secret = RbNaCl::Box.new(remote_eph_pk, local_eph_sk)
  #  shared_secret = local_eph_sk.derive(remote_eph_pk)

    # Let's make sure the derived shared key is safe (non zeros)
  #  raise "Invalid or unsafe shared secret (all-zero) — abort" if shared_secret == ("\x00" * 32)

    # make info include the transcript to bind the keys
  #  transcript = "ssh-like" + local_eph_pk + remote_eph_pk

    # 4) Derive keys, first create a 64 bytes long key material (km) then split it in half
    # obtain so the encription key and the mac_key 
  #  km = OpenSSL::KDF.hkdf(shared_secret, salt: salt, info: transcript, length: 64, hash: "SHA256")
  #end

  # function to check the client_eph_pk (size, validity, non zeros)
  #def key_format_check(raw_key)
  #len = raw_key&.bytesize

  # X25519 public keys are always 32 bytes, guarantee size is correct
  # guarantee key is actually a valid key and also non zeros
  #raise "Invalid public key length: #{len}" if len != RbNaCl::PublicKey::BYTES
  #raise "Failed to read full public key" if client_eph_pk.nil? || raw_key.bytesize != len
  #raise "Rejected all-zero public key" if raw_key == ("\x00" * 32)

    # create an object with the received bytes (client's ephimeral public key)
    # guarantees the key is a proper object and handled safely
  #  begin
  #    client_eph_pk = RbNaCl::PublicKey.new(raw_key)
  #  rescue RbNaCl::LengthError => e
  #    raise "Invalid public key: #{e.message}"
  #  end

  #client_eph_pk
  #end



end
