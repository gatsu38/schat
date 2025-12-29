require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require 'concurrent-ruby'
require_relative 'utils'
require 'pry'
require 'pry-byebug'
require 'sqlite3'

# METHODS
# hello_back_payload_builder
  # build the hello back payload
# receive_hello
  # used to receive the hello message from client containing the client nonce
# hello_client
  # executes the hello client protocol, after this a secret is shared
# run
  # spawns a new thread for each new client connection
# shutdown
  # safe database shutdown

DB_FILE = '/home/kali/schat_db/schat.db'
HOST_KEYS = 'host_keys'
EPH_HOST_KEYS = 'host_ephemeral_keys'
CLIENTS_INFO = 'clients_pub_keys'
CLIENTS_PUB_EPHEMERAL_KEYS = 'clients_eph_pub_keys'
NONCES = 'nonces'
PROTOCOL_NAME = "myproto-v1"
MAX_PROTO_FIELD = 30
MSG_CLIENT_HELLO_ID = "\x01"
MSG_SERVER_HELLO_ID = "\x02"
MSG_CLIENT_HELLO_ID2 = "\x03"
# used for error handling
class BlobReadError < StandardError; end
class BlobSizeError < BlobReadError; end

# === Server ===
class SecureServer
  include Utils

  # usfed to receive the hello message from client   
  def receive_hello(sock)
    puts "receive hello nonce"
    blob = read_blob(sock, timeout: 10)
    raise IOError, "wrong hello size" if blob.bytesize != 30 + 1 + 24
    offset = 0

    # 1) Read protocol name
    raise IOError, "Blob too short for protocol name" if blob.bytesize < offset
    client_protocol_name = read_exact(blob, 0, 30)
    offset += 30

    protocol_start = protocol_name_builder(PROTOCOL_NAME, MAX_PROTO_FIELD)

    unless client_protocol_name == protocol_start
      raise IOError, "Protocol mismatch: #{protocol_id.inspect}"
    end

    # 2) Read message type (1 byte)
    raise IOError, "Blob too short for message type" if blob.bytesize < offset + 1
    msg_type = blob.getbyte(offset)
    offset += 1

    unless msg_type == MSG_CLIENT_HELLO_ID.getbyte(0)
      raise IOError, "Unexpected message type: #{msg_type}"
    end

    # 3) Remaining bytes are the nonce
    client_nonce = read_exact(blob, offset, 15)

#    begin
#      db.execute("INSERT INTO #{NONCES} (nonce) VALUES (?)", [client_nonce])
#    rescue SQLite3::ConstraintException
#      raise ProtocolError, "Replay detected"
#    end

    # Optional sanity check
    unless client_nonce.bytesize == 15
      raise IOError, "Invalid nonce size: #{nonce.bytesize}"
    end
    client_nonce
  end


  # handles a single client 
  def hello_client(sock)

#    DB = SQLite3::Database.new(DB_FILE)
#    DB.results_as_hash = true

    # Ephemeral X25519 server key pair, one pair per client
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key
    # receive client's first protocol connection: just a nonce "client hello"
    puts "receive client's nonce"
    client_nonce = receive_hello(sock)

    # creates the server_nonce
    server_nonce = RbNaCl::Random.random_bytes(15)
    
    # create a signature only valid for that nonce
    signature = sig_builder(client_nonce, eph_pk, server_nonce, "server", MSG_SERVER_HELLO_ID)

    # create the payload to be sent together with the signature in order
    # for the client to verify the server's authenticity 
    hello_back_payload = hello_back_payload_builder(signature, eph_pk, server_nonce, "server", MSG_SERVER_HELLO_ID)    

    # send the hello back containing the signature and the server nonce among other
    puts "send hello back"
    write_all(sock, hello_back_payload)

    # receive the signature and what's required to verify it
    puts "waiting for the client's signature"
    client_hello_back_payload = read_blob(sock, timeout: 10)

    # create the protocol name + padding
    protocol_start = protocol_name_builder(PROTOCOL_NAME, MAX_PROTO_FIELD)

    # verify client's identity and obtain keys
    client_info = peer_identity_verification(server_nonce, protocol_start, client_hello_back_payload, "client", MSG_CLIENT_HELLO_ID2)

    client_pk = client_info[:remote_pk]
    
    client_eph_pk = client_info[:remote_eph_pk]    

    server_box = RbNaCl::Box.new(client_eph_pk, eph_sk)
    {client_nonce: client_nonce, server_nonce: server_nonce, server_box: server_box, client_ehp_pk: client_epk_pk, client_pk: client_pk}
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

  def handle_client()
          box = handshake_info[:box]
          client_pk = handshake_info[:client_pk]
          client_eph_pk = handshake_info[:client_eph_pk]
          client_nonce = handshake_info[:client_nonce]
          server_nonce = handshake_info[:server_nonce]

          nonce_session = Session.new("server", server_nonce)
          send_nonce = nonce_session.next_nonce
          ciphertext = box.box(send_nonce, message)

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
            handshake_info  = self.hello_client(client)
            handle_client(handshake_info)

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

