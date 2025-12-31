# reading and writing functions
# as well as checks



#LIST OF FUNCTIONS and classes:
# session class
  # nonce_builder
    # build the nonce to be used in each message nonce + counter
  # next_nonce
    # method to be called each time a new message has to be sent
#------        
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

  # Used to create a valid and unique nonce to be passed to the box
  # the nonce will include a counter that increases with each message sent
  class Session

    def initialize(role, base_nonce)
       unless role == "client" || role == "server"
        raise ProtocolError, "Invalid identity role"
       end
    
      @role = role              
      @base_nonce = base_nonce  
      @counter = 0               
    end

    # method to be called each time a new message has to be sent
    def next_nonce()
      raise "counter overflow" if @counter >= (1 << 64)

      nonce = build_nonce(@base_nonce, @role, @counter)
      @counter += 1
      nonce
    end

    private

    def build_nonce(base_nonce, role_byte, counter)
      raise ArgumentError, "base_nonce must be 15 bytes long" unless base_nonce.bytesize == 15
      raise ArgumentError, "role_byte must fit in 1 byte" unless (0..255).include?(role_byte)
      raise ArgumentError, "counter must fit in 8 bytes" unless counter >= 0 && counter < (1 << 64)

      nonce =
        base_nonce +
        role_byte + 
        [counter].pack("Q>")
    end

    def role_byte
      @role == :client ? "\x01" : "\x02"
    end
  end

    
  

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
    remote_nonce = read_exact(payload, offset, 15)
    offset += 15

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

    # obtain header
    header = read_socket(sock, 4, timeout)

    # sanity check for payload length
    payload_len = header.unpack1("N")  # unpack1 gives an integer directly
    raise BlobSizeError, "Invalid blob size: #{payload_len}" if payload_len < 0 || payload_len > MAX_BLOB_SIZE

    # read payload (exactly blob_len bytes) blob will contain the payload
    payload = read_socket(sock, payload_len, timeout)

    # make sure the full blob has been sent with the exact size
    unless payload.bytesize == payload_len
      raise IOError, "payload length mismatch: expected size: #{header.unpack1("N")}, obtained: #{payload.size}"
    end


    # return the payload
    payload
  end


  # helper method to ensure full_write on the remote socket
  def write_all(sock, payload, timeout: 10, max_attempts: 5)


    # prefix the payload with the whole size of the payload
    data =
      [payload.bytesize].pack("N") +
      payload

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

    true

  end

end

