require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'
require_relative 'builders'
require 'pry'
require 'pry-byebug'
require 'sqlite3'

# LIST OF FUNCTIONS
# the first method called to send a message to another client: computes the shared secret root key
  # e2ee_root_key
# called during hello_client to check if the public key matches the registered server
  # server_fingerprint_check(remote_pk)
# ask the user to provide the server fingerprint, use it later to check the server identity
  # server_fingerprint_registration() 
# initialize the connection with the server
  # hello_server()
# handles the returned value from the server at the end of the user registration
  # def registration_confirmation(confirmation_byte)
# ask the user to provide a valid voucher and also recover the nickname from the db
  # def registration_request(handshake_info, nonce_session)
# the hello method that asks the server to save the 
  # def e2ee_keys_share(handshake_info, nonce_session)
# main method
  # main()
DB_FILE = "/home/kali/schat_db/client.db"
PROTOCOL_NAME = "myproto-v1"
MAX_PROTO_FIELD = 30
MSG_CLIENT_HELLO_ID = "\x01"
MSG_SERVER_HELLO_ID = "\x02"
MSG_CLIENT_HELLO_ID2 = "\x03"
MSG_CLIENT_REGISTRATION = "\x04"
MSG_SERVER_REGISTRATION_CONFIRMED = "\x05"
MSG_CLIENT_EPH_KEY_CHECK = "\x06"
MSG_SERVER_EPH_KEY_CHECK = "\x07" 
MSG_CLIENT_E2EE_KEYS_SHARE = "\x08"
MSG_CLIENT_E2EE_KEYS_REQUEST = "\x09"
MSG_SERVER_E2EE_KEYS_REQUEST_RESPONSE = "\x0a"
MSG_CLIENT_E2EE_FIRST_MESSAGE = "\x0b"
MSG_CLIENT_E2EE_FIRST_MESSAGE_RESPONSE = "\x0c"
MSG_CLIENT_E2EE_ASK_MESSAGES = "\x0d"
MSG_SERVER_E2EE_DELIVER_MESSAGES = "\x0e"
class ProtocolError < StandardError; end

class SecureClient

  include Utils
  include Builders


  # ask the server if there's messages in the queue and fetch them
  def e2ee_ask_messages(handshake_info, nonce_session)
    sock = handshake_info[:sock]
    server_box = handshake_info[:client_box]

    message = MSG_CLIENT_E2EE_ASK_MESSAGES

    sender(sock, server_box, nonce_session, message)

    # obtain server answer
    returned_payload = read_blob(sock)

    # decipher server answer
    plain_text = decipher(returned_payload, server_box)

    e2ee_first_client_to_client

  end
  

  # receive the first message from a different client
  def e2ee_first_client_to_client(message, handshake_info)
    offset = 0

    remote_id_pub_key = read_exact(message, offset, 32)
    offset += 32

    remote_eph_pub_key = read_exact(message, offset, 32)
    offset += 32

    one_time_pub_key = read_exact(message, offset, 32)
    offset += 32

    signature_size_header = read_exact(message, offset, 2)
    signature_size = signature_size_header.unpack1("n")
    offset += 2

    nonce_size_header = read_exact(message, offset, 2)
    nonce_size = nonce_size_header.unpack1("n")
    offset += 2

    ciphertext_size_header = read_exact(message, offset, 4)
    ciphertext_size = ciphertext_size_header.unpack1("N")
    offset += 4

    unless message.bytesize == ciphertext_size + nonce_size + signature_size + 32 + 32 + 32 + 2 + 2 + 4
      raise ProtocolError, "Declared and received size mismatch"
    end

    signature = read_exact(message, offset, signature_size)
    offset += signature_size

    nonce = read_exact(message, offset, nonce_size)
    offset += nonce_size

    ciphertext = read_exact(message, offset, ciphertext_size)
  end


  # the first method called to send a message to another client: derives the root key
  def e2ee_root_key(handshake_info, nonce_session)
    puts "Please provide the username you wish to interact with"
    username = STDIN.gets.strip
   raise ArgumentError, "Wrong username format" unless username.match?(/\A[A-Za-z0-9]{5,20}\z/)

    begin
      db = SQLite3::Database.new(DB_FILE)
      db.results_as_hash = true

      client_info = db.get_first_row("SELECT * FROM clients_info WHERE username = ?", [username])      
      raise "No username found with name #{username}" unless client_info
      remote_id_pub_key = client_info["public_key"]
      remote_eph_pub_key = client_info["signed_prekey_pub"]
      remote_ot_pub_key = client_info["one_time_key"]

      keys = db.get_first_row(<<-SQL)
        SELECT private_signed_prekey AS priv, public_signed_prekey AS pub FROM shared_prekey;
      SQL

      raise "Missing keys" unless keys
      local_eph_pub_key = keys["pub"]
      local_eph_pri_key = keys["priv"]

      identity_secret = dh(remote_id_pub_key, @host_sk.to_bytes)
      session_secret = dh(remote_eph_pub_key, local_eph_pri_key)
      one_time_secret = dh(remote_ot_pub_key, local_eph_pri_key)

      combined_secrets = identity_secret + session_secret + one_time_secret
      root_key = RbNaCl::Hash.sha256(combined_secrets)
      secret_root_box = RbNaCl::SecretBox.new(root_key)

    rescue
      raise ProtocolError, "Something wrong happened with the shared secrets creation."
    end


    nonce = RbNaCl::Random.random_bytes(secret_root_box.nonce_bytes)
    nonce_size = [nonce.bytesize].pack("n")

    message = "my nice message"
    
    ciphertext = secret_root_box.box(nonce, message)
    ciphertext_size = [ciphertext.bytesize].pack("N")

    signature = @host_sk.sign(local_eph_pub_key)
    signature_size = [signature.bytesize].pack("n")
    payload =
      @host_pk.to_bytes +
      local_eph_pub_key +
      remote_ot_pub_key +
      signature_size +
      nonce_size +
      ciphertext_size +
      signature +
      nonce +
      ciphertext
    
    sock = handshake_info[:sock]
    server_box = handshake_info[:client_box]

    username_size = [username.bytesize].pack("C")
    payload_size = [payload.bytesize].pack("N")

    message = 
      MSG_CLIENT_E2EE_FIRST_MESSAGE +
      username_size +
      payload_size +
      username +
      payload
    sender(sock, server_box, nonce_session, message)
    binding.pry
    # obtain server answer
    returned_payload = read_blob(sock)

    # decipher server answer
    plain_text = decipher(returned_payload, server_box)

    response = handler_caller(plain_text)
    
  rescue
    db&.close
  end

  
  # wrapper around the receiver for the e2ee material 
  def e2ee_client_share_receiver_wrapper(payload, handshake_info)
    e_material = e2ee_keys_share_receiver(payload, handshake_info)

    username = e_material[:username].force_encoding("UTF-8")
    client_pub_key = e_material[:pub_key]
    eph_pk = e_material[:eph_pk]
    signature = e_material[:signature]
    one_time_keys = e_material[:otpk]
    otp_amount = e_material[:otp_amount]

    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    raise ProtocolError, "Too many one time keys" unless otp_amount == 1 && one_time_keys.bytesize == 33
    
    otp = read_exact(one_time_keys, 0, 32)
    counter_packed = read_exact(one_time_keys, 32, 1)
    counter = counter_packed.unpack1("C")
    begin
      db.transaction do
      db.execute(
          <<~SQL,
            INSERT INTO clients_info (username, public_key, signed_prekey_pub, signed_prekey_sig, one_time_key) 
            VALUES (?, ?, ?, ?, ?)
          SQL
          [username, client_pub_key, eph_pk, signature, otp]
        )
      end
    rescue SQLite3::ConstraintException
      raise ProtocolError, "client already registered"
    end
  
  ensure
  db&.close
  end


  # method used to establish a connection with a given user
  def e2ee_keys_request(handshake_info, nonce_session)
    puts "Please provide the username you wish to interact with"
    username = STDIN.gets.strip    

    username_size = [username.bytesize].pack("C")

    raise ArgumentError, "Wrong username format" unless username.match?(/\A[A-Za-z0-9]{5,20}\z/)

    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]

    username_payload = 
      MSG_CLIENT_E2EE_KEYS_REQUEST + 
      username_size +
      username
    sender(sock, safe_box, nonce_session, username_payload)

    # obtain server answer
    returned_payload = read_blob(sock)

    # decipher server answer
    plain_text = decipher(returned_payload, safe_box)

    response = handler_caller(plain_text)
  end


  # the hello method that asks the server to save the keys and signature, later used by other clients for e2ee
  def e2ee_keys_share(handshake_info, nonce_session)
    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true 

    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    eph_sk_bytes = eph_sk.to_bytes
    eph_pk_bytes = eph_pk.to_bytes

    signed_prekey_sig = @host_sk.sign(eph_pk_bytes)
    db.execute("INSERT INTO shared_prekey (private_signed_prekey, public_signed_prekey) VALUES (?, ?)",
      [eph_sk_bytes, eph_pk_bytes]
    )

    one_time_prekeys = []

    counter = 1
    50.times do
      sk = RbNaCl::PrivateKey.generate
      pk = sk.public_key

      sk_bytes = sk.to_bytes
      pk_bytes = pk.to_bytes
      db.execute("INSERT INTO one_time_prekeys (one_time_public_key, one_time_private_key, counter) VALUES (?, ?, ?)",
        [pk_bytes, sk_bytes, counter]
      )

      one_time_prekeys << {pk: pk_bytes, counter: counter}
      counter += 1
    end

    begin
      username = db.get_first_value(<<-SQL)
        SELECT username FROM user;
      SQL
    rescue
      raise ArgumentError, "Local username not found"
    end   
    
    # build the payload for e2ee long term public id, the temporary key, the signature and all the one time keys
    # it is hardcoded for the one time keys to be 50 in total
    payload = e2ee_builder(username, @host_pk.to_bytes, eph_pk_bytes, signed_prekey_sig,  one_time_prekeys, 49)

    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]

    message = MSG_CLIENT_E2EE_KEYS_SHARE + payload
    sender(sock, safe_box, nonce_session, message)

    returned_payload = read_blob(sock)


    # decipher server answer
    plain_text = decipher(returned_payload, safe_box)

    digest = RbNaCl::Hash.sha256(payload)
    raise ProtocolError, "Server payload digest mismatch" unless digest == plain_text

  rescue
    db&.close
  end




  # handles the returned value from the server at the end of the user registration
  # the user will know if voucher + username worked out
  def registration_confirmation(confirmation_byte)
    raise ProtocolError unless confirmation_byte.bytesize == 1
    case confirmation_byte
      when "\x01"
      puts "Registration completed successfully"
      return true
      when "\x02"
      puts "Invalid voucher"
      return false
      when "\x03"
      puts "Nickname already registered"
      return false
      when "\x04"
      puts "Invalid nickname, only alphanumeric 1-20(size)"
      return false
      when "\x05"
      puts "Unknown server side error"
      return false
    else
      raise "Unknown server side error response"
    end
  end

  # ask the user to provide a valid voucher and also recover the nickname from the db,
  def registration_request(handshake_info, nonce_session)
    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    # obtain the nickname from the db
    nickname = db.get_first_value(<<-SQL)
      SELECT username FROM user;
    SQL

    raise ArgumentError, "Please register a username first during database setup" unless nickname 

    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]

    # obtain the voucher
    puts "Insert a valid voucher:"
    while true
      input = STDIN.gets
      break unless input
      voucher = input.strip
      if voucher&.match?(/\A([a-f0-9]{30})\z/)
        break
      else
        puts "Invalid voucher, try again"
      end
    end

    # build the package containing the registration data: request_id, nickname, voucher
    registration_data = registration_builder(nickname, voucher)

    # cipher and send the data
    sender(sock, safe_box, nonce_session, registration_data)

    # obtain server answer
    returned_payload = read_blob(sock)

    # decipher server answer
    plain_text = decipher(returned_payload, safe_box)

    # remove the request_id byte and call appropriate function for the server response analysis
    handler_caller(plain_text)
  end


  # called during hello_client to check if the public key matches the registered server
  def server_fingerprint_check(remote_pk)
    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    remote_pk_bytes = remote_pk.to_bytes

    # transform the public key into a human readable fingerprint
    pretty_remote_pk = remote_pk_bytes.unpack1("H*").scan(/.{4}/).join(":")

    # obtain the previously registered info about the server
    server = db.get_first_row("SELECT fingerprint, server_name FROM server_identity WHERE public_key = ?", remote_pk_bytes)

    raise ProtocolError, "Unknown server public key" unless server

    registered_fingerprint = server["fingerprint"]
    registered_server_name = server["server_name"]
    puts "Remote fingerprint and pre-shared fingerprint for #{registered_server_name}:"
    puts "remote:#{pretty_remote_pk}"
    puts "pre   :#{registered_fingerprint}"

  ensure
    db&.close
  end


   # used to establish a safe comunication channel with the server
  def hello_server()

    # Ephemeral client key
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    puts "created: ephemeral private key, public key and signature"

    # establish a connection with the server
    sock = TCPSocket.new(@host, @port)
    puts "TCP connection established"

    # protocol name + padding preparation
    protocol_start = protocol_name_builder(PROTOCOL_NAME, MAX_PROTO_FIELD)

    # create the nonce used to validate the session  
    client_nonce = RbNaCl::Random.random_bytes(15)

    # create the opening message for client hello    
    opening_message =
      protocol_start +
      MSG_CLIENT_HELLO_ID +
      client_nonce

    # send the first nonce to the server "client hello"
    puts "send opening nonce"
    write_all(sock, opening_message)

    # receive the signature and what's needed to verify it 
    puts "waiting for server signature"
    server_hello_back_payload = read_blob(sock)
    # verify server identity and obtain keys + nonce
    server_info = peer_identity_verification(client_nonce, protocol_start, server_hello_back_payload, "server", MSG_SERVER_HELLO_ID)
    # assign server's public key, ephemeral public key and signature
    server_pk = server_info[:remote_pk]
    server_eph_pk = server_info[:remote_eph_pk]
    server_nonce = server_info[:remote_nonce]

    # check if the server public key is the same as the registered one
    server_fingerprint_check(server_pk)

    # create a signature only valid for these nonces
    signature = sig_builder(server_nonce, eph_pk, client_nonce, "client", MSG_CLIENT_HELLO_ID2)

    # create the payload to be sent together with the signature in order
    # for the server to verify the client's authenticity
    hello_back_payload = hello_back_payload_builder(signature, eph_pk, client_nonce, "client", MSG_CLIENT_HELLO_ID2)

    # send the hello back to the server, completing this way the hello protocol
    write_all(sock, hello_back_payload)
    client_box = RbNaCl::Box.new(server_eph_pk, eph_sk)
    {client_nonce: client_nonce, server_nonce: server_nonce, client_box: client_box, server_eph_pk: server_eph_pk, server_pk: server_pk, sock: sock}
  end


  # ask the user to provide the server fingerprint, use it later to check the server identity, this method is called offline
  def server_fingerprint_registration()
    while true
      puts "please insert the server fingerprint"
      fingerprint = gets&.strip.force_encoding("UTF-8")
      puts "please give a name to the server, (only used locally for identification)"
      puts "maximum size 20 characters and only alphanumerical allowed "
      server_name = gets&.strip.force_encoding("UTF-8")

      if server_name&.match?(/\A[A-Za-z0-9]{1,20}\z/) && fingerprint&.match?(/\A(?:[a-f0-9]{4}:){15}[a-f0-9]{4}\z/)
        break
      else
        puts "invalid server name or fingerprint"
        next
      end
    end

    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    hex = fingerprint.delete(":")
    pk_bytes = [hex].pack("H*")

    raise ArgumentError, "Invalid public key length" unless pk_bytes.bytesize == 32

    db.execute("INSERT INTO server_identity (fingerprint, server_name, public_key) VALUES (?, ?, ?)",
      [fingerprint, server_name, pk_bytes]
    )
  ensure
    db&.close
  end


  # the initialization method
  def initialize(host, port)
    @host, @port = host, port

    db = SQLite3::Database.new(DB_FILE)
    db.results_as_hash = true

    host_row = db.get_first_row("SELECT private_key, public_key FROM user")

    raise ProtocolError, "No host key found" unless host_row

    # Long-term host key (Ed25519)
    host_sk_bytes = host_row["private_key"]
    host_pk_bytes = host_row["public_key"]

    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.new(host_sk_bytes)
    @host_pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(host_pk_bytes)
  ensure
    db&.close
  end

# end of the client class  
end

def main
include Utils
  puts "Schat. SecureChat client v1.0"
  puts "Choose an option:"
  puts "1) register server fingerprint on the local db"
  puts "2) register the client with the server"
  puts "3) manually share with the server the keys for e2ee"
  puts "4) obtain the keys for e2ee for a given username"
  puts "5) Starts communication with a given username"
  puts "6) Fetch messages on the server"
  choice = STDIN.gets.strip.to_i
  client = SecureClient.new("127.0.0.1", 2222)

  
  case choice
    when 1
      # - used to register a server with a previously shared public key / fingerprint
      client.server_fingerprint_registration()
      
    when 2
      # -inside handshake info there is all the info concerning the connection:
      # - used to ask the server to register our client nickname and voucher
      handshake_info = client.hello_server()

      # -create and get the nonce ready
      nonce_session = Session.new("server", handshake_info[:client_nonce])

      client.registration_request(handshake_info, nonce_session)
    when 3
      if handshake_info && nonce_session
        client.e2ee_keys_share(handshake_info, nonce_session)
      else
        handshake_info = client.hello_server()
        nonce_session = Session.new("server", handshake_info[:client_nonce])
        client.e2ee_keys_share(handshake_info, nonce_session)
      end
    when 4
      if handshake_info && nonce_session
        client.e2ee_keys_request(handshake_info, nonce_session)
      else
        handshake_info = client.hello_server()
        nonce_session = Session.new("server", handshake_info[:client_nonce])    
        client.e2ee_keys_request(handshake_info, nonce_session)        
      end
    when 5
      if handshake_info && nonce_session
      client.e2ee_root_key(handshake_info, nonce_session)
    else
      handshake_info = client.hello_server()
      nonce_session = Session.new("server", handshake_info[:client_nonce])
      client.e2ee_root_key(handshake_info, nonce_session)
    end
    when 6
      if handshake_info && nonce_session
      client.e2ee_ask_messages(handshake_info, nonce_session)
    else
      handshake_info = client.hello_server()
      nonce_session = Session.new("server", handshake_info[:client_nonce])
      client.e2ee_ask_messages(handshake_info, nonce_session)        
    end
  else
    raise ArgumentError, "non existing choice"
  end
end
  
main
