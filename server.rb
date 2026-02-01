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

include Utils
include Builders


# METHODS
# receive_hello
  # used to receive the hello message from client containing the client nonce
# hello_client
  # executes the hello client protocol, after this a secret is shared
# registrate_new_user(nickname, handshake_info, db)
  # register the user on the db with the publik_key
#  registration_request_handler(message, handshake_info)
  # handle the registration of a new user
#  e2ee_server_request_receiver(username, handshake_info)
  # provides a client with the requested keys for the e2ee for a given user
# handle_client(handshake_info, sock)
  # this method is used to handle all the messages received from a single client after hello
# run
  # spawns a new thread for each new client connection
# shutdown
  # safe database shutdown
# generate_vouchers
  # create the vouchers
puts "Please provide the db password"
MASTER_KEY = prompt_password("DB password: ")
DB_FILE = File.join(Dir.pwd, "schat_db", "schat1.db")
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
MSG_CLIENT_E2EE_KEYS_SHARE = "\x08"
MSG_CLIENT_E2EE_KEYS_REQUEST = "\x09"
MSG_SERVER_E2EE_KEYS_REQUEST_RESPONSE = "\x0a"
MSG_CLIENT_E2EE_FIRST_MESSAGE = "\x0b"
MSG_CLIENT_E2EE_FIRST_MESSAGE_RESPONSE = "\x0c"
MSG_CLIENT_E2EE_ASK_MESSAGES = "\x0d"
MSG_SERVER_E2EE_DELIVER_MESSAGES = "\x0e"
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

  # reads the message ID and calls the appropriate message handler
  def handler_caller(message, handshake_info = nil)
    offset = 0
    id = read_exact(message, offset, 1)
    handled_message = message.byteslice(1..)

    unless id == "\x04"
      db = open_db(DB_FILE)

      handshake_pk = handshake_info[:client_pk].to_bytes
      binding.pry
      recorded_pk = db.get_first_value("SELECT id FROM clients_info WHERE signing_public_key = ?", handshake_pk)
      if recorded_pk.nil?
        raise ProtocolError, "The client is not registered and tries to access members only functionalities"
      end
    end
      
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
      when "\x0e"
      response = e2ee_read_server_messages_blob(handled_message, handshake_info)
    else
      raise ProtocolError, "Unknown message id: #{id.unpack1('H*')}"
    end

  response
  rescue => e
    raise
  ensure
    db&.close  
  end



  # forward messages to the requester
  def e2ee_message_harvester(message, handshake_info)
    db = open_db(DB_FILE)

    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]
    client_signing_pk = handshake_info[:client_pk].to_bytes
    rows = nil
    begin
      db.transaction do
        client_id = db.get_first_value("SELECT id FROM clients_info WHERE signing_public_key = ?", client_signing_pk)
        
        rows = db.execute(<<~SQL, client_id)
          SELECT m.message, c.username AS sender_username
          FROM messages m
          JOIN clients_info c ON m.sender_id = c.id
          WHERE m.recipient_id = ?
          ORDER by m.created_at;
        SQL
      end
    rescue
      raise ProtocolError, "Something wrong happened during db work"
    end
    rows_count = [rows.length].pack("n")
    payload =""
    payload << rows_count
    rows.each do |row|
      username_size = [row["sender_username"].bytesize].pack("C")
      message_size = [row["message"].bytesize].pack("N")
      payload <<
        username_size +
        message_size +
        row["sender_username"] +
        row["message"]
    end
    message = MSG_SERVER_E2EE_DELIVER_MESSAGES + payload
    message
  rescue => e
    raise  
  ensure
    db&.close
  end

  # receive and save a message on the db
  def e2ee_message_receiver(message, handshake_info)
    offset = 0
    
    username_size_header = read_exact(message, offset, 1)
    username_size = username_size_header.unpack1("C")
    offset += 1

    payload_size_header = read_exact(message, offset, 4)
    payload_size = payload_size_header.unpack1("N")
    offset += 4
    
    unless message.bytesize == username_size + payload_size + 4 + 1
      raise ProtocolError "Mismatch size between received and declared"
    end

    username = read_exact(message, offset, username_size)
    recipient = username.force_encoding("UTF-8")
    offset += username_size

    payload = read_exact(message, offset, payload_size)

    sender_signing_pk = handshake_info[:client_pk].to_bytes

    db = open_db(DB_FILE)

    begin
      db.transaction do
        recipient_id = db.get_first_value("SELECT id FROM clients_info WHERE username = ?", recipient)

        sender_id = db.get_first_value("SELECT id FROM clients_info WHERE signing_public_key = ?", sender_signing_pk)
        db.execute(<<~SQL,
          INSERT INTO messages (recipient_id, sender_id, message) VALUES (?, ?, ?);
        SQL
        [recipient_id, sender_id, payload]
        )
      end
    rescue  
      raise ProtocolError, "Something wrong happened operating the database"
    end
  digest = RbNaCl::Hash.sha256(message)
  digest
  rescue => e
    raise
  ensure
    db&.close  
  end

  
  # handle the registration of a new user
  def registration_request_handler(message, handshake_info)
    offset = 0
    signing_pub_key = handshake_info[:client_pk].to_bytes

    nickname_header = read_exact(message, offset, 1)
    nickname_size = nickname_header.unpack1("C")
    offset += 1
    
    nickname = read_exact(message, offset, nickname_size).force_encoding("UTF-8")

    unless nickname.is_a?(String) && nickname.match?(/\A[A-Za-z0-9]{1,20}\z/)
      response_payload = registration_response_builder("\x04")
    end
    
    offset += nickname_size

    transaction_successful = false

    begin
      raise ProtocolError.new("Invalid registration message size", "\x02" ) unless message.bytesize == 1 + nickname_size + 30

      client_voucher = read_exact(message, offset, 30) 
      encoded_voucher = client_voucher.force_encoding("UTF-8")
      db = open_db(DB_FILE)

      db.transaction do
        row_voucher = db.get_first_row(
          "SELECT id FROM vouchers WHERE voucher = ? AND used_at IS NULL",
          encoded_voucher
        )
        
        raise ProtocolError.new("Invalid voucher", "\x02") unless row_voucher
        
        begin
          db.execute(
          "INSERT INTO clients_info (username, signing_public_key)  VALUES (?, ?)",
          [nickname, signing_pub_key]
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
  rescue => e
    raise
  ensure
    db&.close
  end


  # wrapper around the e2ee receiver to make the checks 
  def e2ee_server_share_receiver_wrapper(payload, handshake_info)
    e_material = e2ee_keys_share_receiver(payload, handshake_info)
    username = e_material[:username]
    signing_pub_key = e_material[:signing_pub_key]
    identity_pub_key = e_material[:identity_pub_key]
    signed_pk = e_material[:signed_pk]
    signature = e_material[:signature]
    one_time_keys = e_material[:otpk]
    otp_amount = e_material[:otp_amount]
    
    db = open_db(DB_FILE)

    begin
      client_id = db.get_first_value("SELECT id FROM clients_info WHERE signing_public_key = ?",
        [signing_pub_key]
      )
      db.transaction do
        db.execute(<<~SQL,
          UPDATE clients_info
          SET signed_prekey_pub = ?,
              signed_prekey_sig = ?,
              identity_public_key = ?
          WHERE id = ?
        SQL
        [signed_pk, signature, identity_pub_key, client_id]
        )
        counter = 0
        offset_2 = 0
        otp_amount.times do
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
    rescue
      raise ProtocolError, "Couldn't update the database with the e2ee material"
    end
    digest = RbNaCl::Hash.sha256(payload)
    digest
  rescue => e
    raise
  ensure
    db&.close
  end

  # provides a client with the requested keys for the e2ee for a given user
  def e2ee_keys_request_receiver(payload, handshake_info)
    offset = 0

    username_header = read_exact(payload, 0, 1)
    username_size = username_header.unpack1("C")
    offset += 1

    raise ProtocolError, "The provided username size is invalid" unless username_size <= 20

    username = read_exact(payload, offset, username_size).force_encoding("UTF-8")
  
    unless username.match?(/\A[A-Za-z0-9]{5,20}\z/) 
      raise ProtocolError, "The provided username does not fit the username criteria" 
    end

    db = open_db(DB_FILE)

    username_row = db.get_first_row("SELECT * FROM clients_info WHERE username = ?",
      [username]
    )
    id = username_row["id"]
    username = username_row["username"]
    signing_public_key = username_row["signing_public_key"]
    identity_public_key = username_row["identity_public_key"]
    signed_prekey_pub = username_row["signed_prekey_pub"]
    signed_prekey_sig = username_row["signed_prekey_sig"]

    one_time_key = nil
    db.transaction do
      one_time_key = db.get_first_row(
        <<~SQL,
          UPDATE one_time_prekeys
          SET used = 1
          WHERE id = (
            SELECT id
            FROM one_time_prekeys
            WHERE used = 0 AND client_id = ?
            LIMIT 1
          )
          RETURNING opk_pub, counter
        SQL
        [id]
      )
      raise "No available one-time prekeys" if one_time_key.nil?
    end
    
    # prepare the one time key, is a lil messed up to be compatible with the builder which is used by the client as well
    one_time_prekey = []
    one_time_key = one_time_key.transform_keys(&:to_sym)
    one_time_prekey << {pk: one_time_key[:opk_pub], counter: one_time_key[:counter]}

    payload = e2ee_builder(username, signing_public_key, identity_public_key, signed_prekey_pub, signed_prekey_sig, one_time_prekey, 0)

    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]

    message = MSG_SERVER_E2EE_KEYS_REQUEST_RESPONSE + payload
    message    
  rescue => e
    raise    
  ensure
    db&.close  
  end


  # this method is used to handle all the messages received from a single client after the hello client
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

  # usfed to receive the hello message from client, called from hello_client
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
  rescue => e
    raise
  end


  # handles a single client, used to establish a safe channel with a single client, returns the handshake info
  def hello_client(sock)

    # receive client's first protocol connection: just a nonce "client hello"
    puts "receive client's nonce"
    client_nonce = receive_hello(sock)

    # Ephemeral X25519 server key pair, one pair per client
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

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
  rescue => e
    raise      
  end


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
            e
          ensure
            begin
              sock.close
            rescue StandardError => close_error
              puts "Failed to close the client: #{close_error.message}"
            end  
          end
        end
      end
    rescue => e
      raise  
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

  # initialize the server class
  def initialize(port)

    if !File.exist?(DB_FILE)
      puts "Please run the server_setup.rb file first"
      exit
    end

  
    # ip port and max number of threads
    @port = port
    @pool = Concurrent::FixedThreadPool.new(20)

    db = open_db(DB_FILE)

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

    puts "Do you want new vouchers? Y/N"
    answer_one = gets.chomp.strip.upcase
    if answer_one == 'Y'
      generate_vouchers()
      puts "Do you want to see the available vouchers? Y/N"
      answer_two = gets.chomp.strip.upcase
        if answer_two == 'Y'
          db.execute("SELECT voucher FROM vouchers WHERE used_at IS NULL") do |row|
            puts row[0]
          end
        end
    end
  rescue => e  
    raise
  ensure
    db&.close
  end

# end of the server class
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

  db = open_db(DB_FILE)
  
  unused_count = db.get_first_value(
  <<~SQL
    SELECT COUNT (*) FROM vouchers WHERE used_at IS NULL;
  SQL
  )

  insert_stmt = db.prepare <<~SQL
    INSERT INTO vouchers (voucher) VALUES (?);
  SQL
  
  puts "Unused vouchers already in DB: #{unused_count}"
  puts "Generating #{n} random vouchers"
  n.times do
    seed = RbNaCl::Random.random_bytes(32)
    seed_hash = RbNaCl::Hash.sha256(seed)
    voucher = seed_hash.unpack1("H*")[0, 30].force_encoding("UTF-8")

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
SecureServer.new(2222).run

