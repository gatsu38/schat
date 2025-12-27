# reading and writing functions
# as well as checks

#LIST OF FUNCTIONS:
# hello_back_payload_builder
  # build the hello back
# peer identity verification
  # verify remote identity and connection genuinity
# sig_builder
  # build the signature to send back to the client after hello
# protocol_name_builder 
  # builder for client hello, outputs protocol name + padding
# read_exact
    # helper function used to read exactly the required size from a buffer
# receive_and_check
  # function to receive public key, ephimeral key and signature
# digest_confirmation
  # send back a hash of the blob to confirm arrival                     
# kex_parser
  # parse the blob to obtain the kex
# handshake_check
  # function to check the validity of the keys and signature
# !!! send_kex
  # !!! this function is used to send the public and ephemeral keys                          
# !!! confirm_kex_arrived
# read_socket
  # method to safely read the TCP socket
# read_blob         
  # function to obtain the full content of the socket
# write_all
  # helper method to ensure full_write on the remote socket

require 'timeout'
require 'rbnacl'
module Utils

MAX_BLOB_SIZE = 16 * 1024 * 1024
MAX_FIELD_SIZE = 1024

  # build the hello back payload
  def hello_back_payload_builder(signature, eph_pk, local_nonce, identity, hello_id)

  protocol_start = protocol_name_builder(PROTOCOL_NAME, MAX_PROTO_FIELD)

    payload =
      protocol_start +
      hello_id +
      identity +
      @host_pk.to_bytes +
      eph_pk.to_bytes +
      local_nonce +
      signature

    payload
  end

  # verify remote identity and connection genuinity
  def peer_identity_verification(nonce, protocol_start, payload, identity, hello_id)
    offset = 0

    # protocol name
    proto = read_exact(payload, offset, 30)
    offset += 30
    raise "protocol mismatch" unless proto == protocol_start

    # message ID
    msg_id = read_exact(payload, offset, 1)
    offset += 1
    raise "Unexpected message type" unless msg_id == hello_id

    # role of the sender
    role = read_exact(payload, offset, 6)
    offset += 6
    raise "Invalid sender role" unless role == identity

    # server public key
    remote_pk_bytes = read_exact(payload, offset, 32)
    offset += 32
    # check quality of the key
    begin
      remote_pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(remote_pk_bytes)
    rescue RbNaCl::CryptoError
      raise ProtocolError, "Invalid Server public key"
    end
    # !!!! TO BE ADD
    # raise "Untrusted server key" unless server_pk_bytes == @trusted_server_pk

    # server eph pk
    remote_eph_pk_bytes = read_exact(payload, offset, 32)
    offset += 32
    begin
      remote_eph_pk = RbNaCl::PublicKey.new(remote_eph_pk_bytes)
    rescue RbNaCl::CryptoError
      raise ProtocolError, "Invalid server ephemeral public key"
    end

    # server nonce
    remote_nonce = read_exact(payload, offset, RbNaCl::Box.nonce_bytes)
    offset += RbNaCl::Box.nonce_bytes

    # check if the nonce is non zero
    if remote_nonce.bytes.all? { |b| b == 0 }
      raise ProtocolError, "Invalid server nonce (all-zero)"
    end

    # signature
    remote_signature = read_exact(payload, offset, 64)
    offset += 64
    raise "Trailing bytes detected" unless offset == payload.bytesize

    # rebuild transcript
    transcript =
      [PROTOCOL_NAME.bytesize].pack("n") +
      PROTOCOL_NAME +
      hello_id +
      identity +
      remote_pk_bytes +
      nonce +
      remote_nonce +
      remote_eph_pk_bytes
    # signature verification
    unless remote_pk.verify(remote_signature, transcript)
      raise "Server signature verification failed"
    end
    puts "signature verified"
    {remote_pk: remote_pk, remote_eph_pk: remote_eph_pk, remote_nonce: remote_nonce}
  end


  # build the signature to send back to the client after hello
  def sig_builder(peer_nonce, eph_pk, local_nonce, identity, hello_id)

  unless identity == "client" || identity == "server"
    raise ProtocolError, "Invalid identity role"
  end

    puts "building signature for server authentication"
    transcript =
      [PROTOCOL_NAME.bytesize].pack("n") +
      PROTOCOL_NAME +
      hello_id +
      identity +
      @host_pk.to_bytes +
      peer_nonce +
      local_nonce +
      eph_pk.to_bytes
    sig = @host_sk.sign(transcript)
    sig
  end


  # builder for client hello: protocol name + padding preparation
  def protocol_name_builder(current_protocol_name, max_protocol_size)
    protocol_start = current_protocol_name.b
    if protocol_start.bytesize > max_protocol_size
      raise ArgumentError, "PROTOCOL_NAME too long (max #{MAX_PROTO_FIELD} bytes)"
    end
    padding_len = max_protocol_size - protocol_start.bytesize
    padding = "\x00" * padding_len  
    protocol_name_with_padding =
      protocol_start +
      padding
    protocol_name_with_padding
  end

  # helper function used to read exactly the required size from a buffer
  def read_exact(buf, offset, len)
  chunk = buf[offset, len]
    if chunk.nil? || chunk.bytesize != len
      raise ProtocolError, "Truncated #{field_name}"
    end
  chunk
  end


  # function to receive public key, ephimeral key and signature
  def receive_and_check(sock)
    raise ArgumentError, "Socket is nil" if sock.nil?
    
    returned_blob = read_blob(sock)

    # send back hash of blob
    digest_confirmation(sock, returned_blob)

    # parse the blob into 4 different contents 
    keys = kex_parser(returned_blob)
    rescue IOError, Errno::EPIPE => e
      warn "Socket read failed: #{e.class} - #e.message}"
      raise
    rescue StandardError => e
      warn "Unexpected error during read_kex: #{e.class} - #{e.message}"
      raise  
  end 


  # send back a hash of the blob to confirm arrival 
  def digest_confirmation(sock, blob)
    raise ArgumentError, "Socket is nil" if sock.nil?
    raise ArgumentError, "Blob is nil" if blob.nil?

  unless blob.is_a?(String)
    raise TypeError, "Expected raw bytes (String), got #{blob.class}"
  end

  blob = blob.b  # enforce binary encoding

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


  # this function is used to send the public and ephemeral keys 
  def send_kex(sock, *blobs)

    # check sock not nil
    raise ArgumentError, "Socket is nil" if sock.nil?
    begin

      # check blob content not nil
      raise ArgumentError, "Kex argument missing" if blobs.nil? || blobs.empty?

      payload = +""

      blobs.each do |data|
        unless data.is_a?(string)
          raise TypeError, "Expected Raw bytes (string), got #{data.class}"
        end
        
        data = data.b
      payload << [data.bytesize].pack("N")
      payload << data
      end  

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

  # method to safely read the TCP socket
  def read_socket(sock, n, timeout)
    buf = +""
    
    while buf.bytesize < n
      ready = IO.select([sock], nil, nil, timeout)
      raise Timeout::Error, "Timeout while reading #{n} bytes from socket" unless ready

      begin
        chunk = sock.readpartial(n - buf.bytesize)
      rescue EOFError
        raise EOFError, "Connection closed while reading"
      end
      buf << chunk
    end
    buf  
  end
  

  # function to obtain the full content of the socket
  def read_blob(sock, timeout: 10, max_attempts:5)
    attempts = 0
    
    begin
      attempts += 1

      # obtain header
      header = read_socket(sock, 4, timeout)

      # sanity check for payload length
      payload_len = header.unpack1("N")  # unpack1 gives an integer directly
      raise BlobSizeError, "Invalid blob size: #{payload_len}" if payload_len < 0 || payload_len > MAX_BLOB_SIZE

      flag_in = read_socket(sock, 1, timeout)
      unless ["\x01", "\x02"].include?(flag_in)
        raise IOError, "Invalid flag value: #{flag.inspect}"
      end

      # read payload (exactly blob_len bytes) blob will contain the payload
      payload = read_socket(sock, payload_len, timeout)

      # make sure the full blob has been sent with the exact size
      unless payload.bytesize == payload_len
        raise IOError, "payload length mismatch: expected size: #{header.unpack1("N")}, obtained: #{payload.size}"
      end

      # send digest confirmation
      if flag_in == "\x01"
        digest = RbNaCl::Hash.sha256(payload)
        write_all(sock, digest, false)
      end

      # return the payload
      payload

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
  def write_all(sock, payload, confirmation_flag, timeout: 10, max_attempts: 5)

  flag = confirmation_flag ? "\x01" : "\x02"

    # prefix the payload with the whole size of the payload
    data =
      [payload.bytesize].pack("N") +
      flag +
      payload

    expected_digest = RbNaCl::Hash.sha256(payload)
  
    total_written_on_sock = 0
    attempts_on_sock = 0
    attempts_on_wire = 0 
    begin
      # tries to write as many bytes as possible and doesn't block the server
      while total_written_on_sock < data.bytesize
        written = sock.write_nonblock(data[total_written_on_sock..-1])
        total_written_on_sock += written
      end

    # in case of failure wait untill the socket is writable, 5 maximum attempts
    rescue IO::WaitWritable
      attempts_on_sock += 1
        if attempts_on_sock >= 5
          sock.close
          abort IOError, "Socket not writable after 5 attempts. Sock closed. Schat closed" 
        end  
      IO.select(nil, [sock], nil, timeout)
        raise IOError, "Socket not writable within timeout"      
      retry
    end

    # expect digest from peer
    return true unless confirmation_flag

    digest_blob = read_blob(sock)

    unless digest_blob.bytesize == 32
      raise IOError, "Invalid digest size: #{digest_blob.bytesize}"
    end

    unless digest_blob == expected_digest
      raise SecurityError, "Digest mismatch (integrity check failed)"
    end

    true

  end

end
