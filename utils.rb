# reading and writing functions
# as well as checks



#LIST OF FUNCTIONS and classes:
# session class
  # nonce_builder
    # build the nonce to be used in each message nonce + counter
  # next_nonce
    # method to be called each time a new message has to be sent
#------      
# dh
  # takes a public and a private key and returns the shared secret, is a helper function, a wrapper
# handler_caller
  # reads the message ID and calls the appropriate message handler  
# e2ee_receiver(payload, handshake_info)
  # obtains the keys needed for the e2ee between two clients
# decipher
  # unbox the messages
# sender
    # cipher the content, pack it with the nonce, send it, update nonce, get confirmation
# peer identity verification
  # verify remote identity and connection genuinity
# read_exact
    # helper function used to read exactly the required size from a buffer
# receive_and_check
  # function to receive public key, ephimeral key and signature
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

      @role = role == "client" ? "\x01" : "\x02"              
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
      raise ArgumentError, "role_byte must be 1 byte long" unless role_byte.bytesize == 1
      raise ArgumentError, "counter must fit in 8 bytes" unless counter >= 0 && counter < (1 << 64)

      nonce =
        base_nonce +
        role_byte + 
        [counter].pack("Q>")
    end

    def role_byte
      @role == :client ? "\x01" : "\x02"
    end
  # end of session class
  end

  # helper wrapper to obtain the shared secret from two keys
  def dh(public_key, private_key)
    box = RbNaCl::Box.new(public_key, private_key)

    out = "\x00" * 32
    returned = box.crypto_box_curve25519xsalsa20poly1305_beforenm(out, public_key, private_key)
    raise "Shared secret creation failed" unless returned == 0
    out
  end


  # reads the message ID and calls the appropriate message handler
  def handler_caller(message, handshake_info = nil)
    offset = 0
    id = read_exact(message, offset, 1)
    handled_message = message.byteslice(1..)
    
    case id
      when "\x04"
      response = registration_request_handler(handled_message, handshake_info) 
      when "\x05"
      response = registration_confirmation(handled_message)
      when "\x08"
      response = e2ee_server_share_receiver_wrapper(handled_message, handshake_info)
      when "\x09"
      response = e2ee_keys_request_receiver(handled_message, handshake_info)
      when "\x0a"
      response = e2ee_client_share_receiver_wrapper(handled_message, handshake_info)
      when "\x0b"
      response = e2ee_message_receiver(handled_message, handshake_info)
      when "\x0d"
      response = e2ee_message_harvester(handled_message, handshake_info)
    else
      raise ProtocolError, "Unknown message id: #{id.unpack1('H*')}"  
    end
  response          
  end


  # obtains the keys needed for the e2ee between two clients
  def e2ee_keys_share_receiver(payload, handshake_info)
    offset = 0
    username_size_header = read_exact(payload, offset, 1)
    username_size = username_size_header.unpack1("C")
    offset += 1
    raise ProtocolError unless username_size >= 5 && username_size <= 20

    username = read_exact(payload, offset, username_size)
    offset += username_size

    client_pub_key_bytes = read_exact(payload, offset, 32)
    client_pub_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(client_pub_key_bytes)
    offset += 32

    eph_pk = read_exact(payload, offset, 32)
    offset += 32

    signature_size_packed = read_exact(payload, offset, 2)
    signature_size = signature_size_packed.unpack1("n")
    offset += 2
    signature = read_exact(payload, offset, signature_size)
    offset += signature_size

    unless client_pub_key.verify(signature, eph_pk)
      raise ProtocolError, "ephemeral pub key mismatch with signature and client public key"
    end

    otp_amount_packed = read_exact(payload, offset, 2)
    otp_amount = otp_amount_packed.unpack1("n")
    offset += 2

    otp_size_packed = read_exact(payload, offset, 4)
    otp_size = otp_size_packed.unpack1("N")
    offset += 4

    raise ProtocolError, "Wrong otp size" unless otp_size == otp_amount * (32 + 1)

    unless payload.bytesize == 1 + username_size + 32 + 32 + 2 + signature_size + 2 + 4 + otp_size
      raise ProtocolError, "received wrong size for e2ee hello"
    end

    one_time_keys = read_exact(payload, offset, otp_size)

    e_material = {username: username, pub_key: client_pub_key_bytes, eph_pk: eph_pk, signature: signature, otpk: one_time_keys, otp_amount: otp_amount}

    e_material
  end

  
  # unbox the messages
  def decipher(blob, box)

    blob_size = blob.bytesize
    offset = 0
    nonce = read_exact(blob, offset, 24)
    offset += 24

    cipher_header = read_exact(blob, offset, 4)
    cipher_size = cipher_header.unpack1("N")
    offset += 4

    raise BlobSizeError, "Invalid blob size: #{cipher_size}" if cipher_size < 0 || cipher_size > MAX_BLOB_SIZE
    raise BlobSizeError, "Mismatch between declared cipher size and received package size" if cipher_size != blob.bytesize - 24 - 4
    cipher = read_exact(blob, offset, cipher_size)
    plain_text = box.open(nonce, cipher)
    plain_text
  end


  # cipher the content, pack it with the nonce, send it, update nonce, get confirmation
  def sender(sock, box, nonce_session, message)
    nonce = nonce_session.next_nonce
    ciphertext = box.box(nonce, message)

    payload =
      nonce +
      [ciphertext.bytesize].pack("N") +
      ciphertext

    write_all(sock, payload)
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




  # helper function used to read exactly the required size from a buffer
  def read_exact(buf, offset, len)
    chunk = buf[offset, len]
    if chunk.nil? || chunk.bytesize != len
      raise ProtocolError, "Truncated chunk #{chunk}"
    end
    chunk
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

