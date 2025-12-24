require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require 'concurrent-ruby'
require_relative 'utils'
require 'pry'
require 'pry-byebug'

PROTOCOL_NAME = "myproto-v1"
MSG_CLIENT_HELLO_ID = "\x01"
MSG_SERVER_HELLO_ID = "\x02"

# used for error handling
class BlobReadError < StandardError; end
class BlobSizeError < BlobReadError; end

# === Server ===
class SecureServer
  include Utils

  def sig_builder(client_nonce, eph_pk, server_nonce)
    puts "building signature for server authentication"
    transcript = [PROTOCOL_NAME.bytesize].pack("n") + 
      PROTOCOL_NAME + 
      MSG_SERVER_HELLO_ID +
      "server" + 
      @host_pk.to_bytes + 
      client_nonce + 
      server_nonce + 
      eph_pk.to_bytes
      
    sig = @host_sk.sign(transcript)
    sig
  end

  def hello_back_payload_builder(signature, eph_pk, server_nonce)
    payload = 
      [PROTOCOL_NAME.bytesize].pack("n") + 
      PROTOCOL_NAME + 
      MSG_SERVER_HELLO_ID +
      "server" + 
      @host_pk.to_bytes + 
      eph_pk.to_bytes + 
      server_nonce + 
      signature
      
    payload
  end

  # used to receive the hell message from client   
  def receive_hello(sock)
    blob = read_blob(sock)
    offset = 0

    # 1) Read protocol name length (2 bytes)
    raise IOError, "Blob too short for protocol length" if blob.bytesize < 2    
    proto_len = blob.unpack1("n")
    offset += 2

    # 2) Read protocol name
    raise IOError, "Blob too short for protocol name" if blob.bytesize < offset + proto_len
    client_protocol_name = blob.byteslice(offset, proto_len)
    offset += proto_len

    unless client_protocol_name == PROTOCOL_NAME
      raise IOError, "Protocol mismatch: #{protocol_id.inspect}"
    end

    # 3) Read message type (1 byte)
    raise IOError, "Blob too short for message type" if blob.bytesize < offset + 1
    msg_type = blob.getbyte(offset)
    offset += 1

    unless msg_type == MSG_CLIENT_HELLO_ID.getbyte(0)
      raise IOError, "Unexpected message type: #{msg_type}"
    end

    # 4) Remaining bytes are the nonce
    client_nonce = blob.byteslice(offset, blob.bytesize - offset)

    # Optional sanity check
    unless client_nonce.bytesize == RbNaCl::Box.nonce_bytes
      raise IOError, "Invalid nonce size: #{nonce.bytesize}"
    end
    client_nonce
  end


  # handles a single client 
  def handle_client(sock)

    # Ephemeral X25519 server key pair, one pair per client
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    # receive client's first protocol connection: just a nonce
    client_nonce = receive_hello(sock)

    # creates the server_nonce
    server_nonce = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
    
    # create a signature only valid for that nonce
    signature = sig_builder(client_nonce, eph_pk, server_nonce)

    # create the payload to be sent together with the signature in order to verify the server's authenticity 
    hello_back_payload = hello_back_payload_builder(signature, eph_pk, server_nonce)    
    binding.pry
    # send the first nonce to the client
    write_all(sock, hello_back_payload)
    
    puts "start kex sending"
    # Send public signing key and ephemeral key (kex)
    send_kex(sock, @host_pk, eph_pk, sig, nonce)

    # Receive host pub, server eph pub, signature
    puts "start kex receiving"
    keys = receive_and_check(sock)

    # kex_confirmation_sender(sock)
    
    puts "kex received"
    client_pk = keys[:public_key]
    client_eph_pk = keys[:ephemeral_key]
    client_sig = keys[:sig]
    # call function to create the key materials
    # obtain encription and mac keys from the key material

    server_box = RbNaCl::Box.new(client_eph_pk, eph_sk)
    message = read_blob(sock)
    plaintext = server_box.decrypt(nonce, message)
    puts "#{plaintext}"
    
    sock.write("OK")
    sock.close
  end

				

  # create a Ed25519 private key (signing key)
  # used to sign the server's ephimeral public key
  # @host_pk contains the derived public key
  # !!!!!!!! this part has to be changed for proper host key handling !!!!!!!!
  # !!!!!!!! TO FIX !!!!!!!!!
  def initialize(port)
    # ip port and max number of threads
    @port = port
    @pool = Concurrent::FixedThreadPool.new(20)

    # Long-term host key (Ed25519)
    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.generate
    @host_pk = @host_sk.verify_key
  end  


  # handles the incoming connections 
  # spawns a new thread for each new client connection
  def run
    begin
    server = TCPServer.new(@port)
    puts "Server listening on port #{@port}"

      loop do
        # client is the tcp connection 
        puts "ready to accept new connection"
        client = server.accept
        puts "new connection accepted"
        # Submit the client handling job to the pool
        @pool.post do
        puts "New thread opened"
          begin
            self.handle_client(client)
          rescue StandardError => e
            begin
              client.write "connection failed: #{e.message}"
            rescue => send_error
              puts "failed to send error to the client: #{send_error.message}"
            end
            puts "Thread exception #{e.class} - #{e.message}"
            puts e.backtrace.join("\n")
          ensure
            begin
              client.close
            rescue StandardError => close_error
              puts "Failed to close the client: #{close_error.message}"
            end  
          end
        end
      end
    ensure
      self.shutdown(server) if server
    end
  end

  # safe database shutdown
  def shutdown(server)
    begin
      puts "\nShutting down server..."

      # Try to close the TCP server socket
      begin
        server.close
        puts "Server socket closed."
      rescue => e
        puts "Warning: failed to close server socket - #{e.class}: #{e.message}"
      end

      # Try to shut down the thread pool gracefully
      begin
        @pool.shutdown
        @pool.wait_for_termination
        puts "Thread pool shut down cleanly."
      rescue => e
        puts "Warning: thread pool shutdown failed - #{e.class}: #{e.message}"
      end

      puts "Server stopped gracefully."

    rescue => e
      # This catches *any* error during shutdown
      puts "Unexpected error during shutdown: #{e.class} - #{e.message}"
    ensure
      # Always exit even if errors occurred
      exit
    end
  end

end

# non necessariamente instanziabile
SecureServer.new(2222).run

