require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require 'concurrent-ruby'
require_relative 'utils'
require_relative 'builders'
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
# decipher
  # deciphers the received message
# run
  # spawns a new thread for each new client connection
# shutdown
  # safe database shutdown
# generate_vouchers
  # create the vouchers
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
MSG_CLIENT_REGISTRATION = "\x04"
MSG_SERVER_REGISTRATION_RESPONSE = "\x05"
MSG_CLIENT_EEE_HELLO = "\x08"
# used for error handling
class BlobReadError < StandardError; end
class BlobSizeError < BlobReadError; end

class ProtocolError < StandardError
  attr_reader :code

  def initialize(message, code)
    super(message)
    @code = code
  end
end

# === Server ===
class SecureServer
  include Utils
  include Builders

  # usfed to receive the hello message from client   
  def receive_hello(sock)
    puts "receive hello nonce"
    blob = read_blob(sock)
    raise IOError, "wrong hello size" if blob.bytesize != 30 + 1 + 15
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

    # Optional sanity check
    unless client_nonce.bytesize == 15
      raise IOError, "Invalid nonce size: #{nonce.bytesize}"
    end
    client_nonce
  end

  # register the user on the db with the publik_key
  def registrate_new_user(nickname, handshake_info, db)
    #db = SQLite3::Database.new(DB_FILE)
    #db.results_as_hash = true

    client_pk = handshake_info[:client_pk].to_bytes        

    db.execute(
      "INSERT INTO clients_info (username, public_key)  VALUES (?, ?)",
      [nickname, client_pk]
    )

    raise ProtocollError, "voucher update on db: ERROR" unless db.changes == 1
    
  end

  # handle the registration of a new user
  def registration_request_handler(message, handshake_info)
    offset = 0
    client_pk = handshake_info[:client_pk].to_bytes\

    nickname_header = read_exact(message, offset, 1)
    nickname_size = nickname_header.unpack1("C")
    offset += 1
    
    nickname = read_exact(message, offset, nickname_size).force_encoding("ASCII")

    unless nickname.is_a?(String) && nickname.match?(/\A[A-Za-z0-9]{1,20}\z/)
      response_payload = registration_response_builder("\x04")
    end
    
    offset += nickname_size

    transaction_successful = false

    begin
      raise ProtocolError.new("Invalid registration message size", "\x02" ) unless message.bytesize == 1 + nickname_size + 30

      client_voucher = read_exact(message, offset, 30) 
      encoded_voucher = client_voucher.force_encoding("UTF-8")
      db = SQLite3::Database.new(DB_FILE)
      db.results_as_hash = true

      db.transaction do
        row_voucher = db.get_first_row(
          "SELECT id FROM vouchers WHERE voucher = ? AND used_at IS NULL",
          client_voucher
        )
        
        raise ProtocolError.new("Invalid voucher", "\x02") unless row_voucher
        
        begin
          db.execute(
          "INSERT INTO clients_info (username, public_key)  VALUES (?, ?)",
          [nickname, client_pk]
          )
        rescue SQLite3::ConstraintException
          raise ProtocolError.new("Username already exists", "\x03")
        end
             
        db.execute(
          "UPDATE vouchers SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
          row_voucher["id"]
        )

        raise ProtocolError.new("Unknown error", "\x05") if db.changes != 1
        transaction_successful = true

      end    
    rescue ProtocolError => e
      response_payload = registration_response_builder(e.code)    
    end
  if transaction_successful
    response_payload = registration_response_builder("\x01")
  end

  response_payload  

  ensure
    db&.close
  end

  def eee_receiver(payload, handshake_info)
      
    client_pub_key = handshake_info[:client_pk]
    offset = 0
    
    eph_pk = read_exact(payload, offset, 32)
    offset += 32

    signature_size_packed = read_exact(payload, offset, 2)
    signature_size = signature_size_packed.unpack1("n")
    offset += 2
    signature = read_exact(payload, offset, signature_size)
    offset += signature_size

    binding.pry
    unless client_pub_key.verify(signature, eph_pk)
      raise ProtocolError, "ephemeral pub key mismatch with signature and client public key"
    end
    
    otp_size_packed = read_exact(payload, offset, 4)
    otp_size = otp_size_packed.unpack1("N")
    offset += 4

    raise ProtocolError, "Wrong otp size" unless otp_size 50 * (32 + 1)

    unless payload.bytesize == 32 + 2 + signature_size + 4 + otp_size
      raise ProtocolError, "received wrong size for e2ee hello" 
    end
    
    one_time_keys = read_exact(payload, offset, otp_size)  
    binding.pry
    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    binding.pry
    client_id = db.get_first_value("SELECT id FROM clients_info WHERE public_key = ?",
      [client_pub_key]
    )

    raise ProtocolError, "unknown client" unless client_id
      
    db.transaction do
      db.execute("UPDATE clients_info SET signed_prekey_pub = ? WHERE id =?",
        [eph_pk, client_id]
      )  
      counter = 0
      offset_2 = 0
      50.times do
        binding.pry
        otp = read_exact(one_time_keys, offset_2, 32)
        offset_2 += 32
        counter_packed = read_exact(one_time_keys, offset_2, 1)
        counter = counter_packed.unpack1("C")
        offset_2 += 1
        db.execute("INSERT INTO one_time_prekeys (opk_pub, counter, client_id) VALUES (?, ?, ?)",
          [otp, counter, client_id] 
        )
      end  
    end
  ensure
  db&.close    
  end
  
  # handles a single client 
  def hello_client(sock)

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
    client_hello_back_payload = read_blob(sock)

    # create the protocol name + padding
    protocol_start = protocol_name_builder(PROTOCOL_NAME, MAX_PROTO_FIELD)

    # verify client's identity and obtain keys
    client_info = peer_identity_verification(server_nonce, protocol_start, client_hello_back_payload, "client", MSG_CLIENT_HELLO_ID2)

    client_pk = client_info[:remote_pk]
    
    client_eph_pk = client_info[:remote_eph_pk]    
    server_box = RbNaCl::Box.new(client_eph_pk, eph_sk)
    {client_nonce: client_nonce, server_nonce: server_nonce, server_box: server_box, client_eph_pk: client_eph_pk, client_pk: client_pk}
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

    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    host_row = db.get_first_row("SELECT private_key, public_key FROM host_keys")

    raise ProtocolError, "No host key found" unless host_row
    
    # Long-term host key (Ed25519)
    host_sk_bytes = host_row["private_key"]
    host_pk_bytes = host_row["public_key"]

    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.new(host_sk_bytes)
    @host_pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(host_pk_bytes)

    host_pk_hex = host_pk_bytes.unpack1("H*")
    pretty = host_pk_hex.scan(/.{4}/).join(":")
    puts "Server fingerprint: #{pretty}"
  ensure
    db&.close
  end  

  # this method is used to handle all the messages received from a single client after hello
  def handle_client(handshake_info, sock)

    server_nonce = handshake_info[:server_nonce]
    client_nonce = handshake_info[:client_nonce]
    # create a nonce to be sent with each package
    nonce_session = Session.new("server", server_nonce)

    # extract all the handshake_info
    #     {client_nonce: client_nonce, server_nonce: server_nonce, server_box: server_box, client_ehp_pk: client_epk_pk, client_pk: client_p>
    box = handshake_info[:server_box]
    client_eph_pk = handshake_info[:client_eph_pk]
    client_pk = handshake_info[:client_pk]
    
    loop do
      begin
        blob = read_blob(sock)                    
        message = decipher(blob, box)
        response = handler_caller(message, handshake_info)
        sender(sock, box, nonce_session, response)
      rescue Timeout::Error
        next
      rescue EOFError
        break
      rescue StandardError => e
        puts "Error during message reception: #{e.message}"
        break
      end
    end
  end

  # handles the incoming connections 
  # spawns a new thread for each new client connection
  def run
    begin
    tcp_server = TCPServer.new(@port)
    puts "Server listening on port #{@port}"

      loop do
        # client is the tcp connection 
        puts "ready to accept new connection"
        sock = tcp_server.accept
        puts "new connection accepted"
        # Submit the client handling job to the pool
        @pool.post do
        puts "New thread opened"
          begin
            # First: the handshake with the client
            handshake_info  = self.hello_client(sock)
            # Second: a method that constantly listens for incoming messages from the client
            handle_client(handshake_info, sock)
            
          rescue StandardError => e
            begin
              sock.write "connection failed: #{e.message}"
            rescue => send_error
              puts "failed to send error to the client: #{send_error.message}"
            end
            puts "Thread exception #{e.class} - #{e.message}"
            puts e.backtrace.join("\n")
          ensure
            begin
              sock.close
            rescue StandardError => close_error
              puts "Failed to close the client: #{close_error.message}"
            end  
          end
        end
      end
    ensure
      self.shutdown(tcp_server) if tcp_server
    end
  end

  # safe database shutdown
  def shutdown(tcp_server)
    begin
      puts "\nShutting down server..."

      # Try to close the TCP server socket
      begin
        tcp_server.close
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

# generate vouchers to be used by clients to register
def generate_vouchers()
  n = nil
  puts "Choose how many vouchers to generate (1-100): "
  loop do
    input = STDIN.gets&.chomp

    next  unless input =~ /\A\d+\z/

    n = input.to_i
    break if n.between?(1, 100)
    puts "Number of vouchers to generate too high"
  end

  db = SQLite3::Database.new(DB_FILE)
  db.results_as_hash = true
  
  unused_count = db.get_first_value(<<-SQL)
    SELECT COUNT(*) FROM vouchers WHERE used_at IS NULL;
  SQL

  insert_stmt = db.prepare <<-SQL
    INSERT INTO vouchers (voucher) VALUES (?);
  SQL
  
  puts "Unused vouchers already in DB: #{unused_count}"
  puts "Generating #{n} random vouchers"
  n.times do
    seed = RbNaCl::Random.random_bytes(32)
    seed_hash = RbNaCl::Hash.sha256(seed)
    voucher = seed_hash.unpack1("H*")[0, 30]

    begin
      insert_stmt.execute(voucher)
    rescue SQLite3::ConstraintException
      retry
    end
  end
  insert_stmt.close
  puts "New vouchers issued"

ensure
  db&.close  
end



# non necessariamente instanziabile
#generate_vouchers()
SecureServer.new(2222).run

