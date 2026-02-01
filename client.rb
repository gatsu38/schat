#require 'socket'
require 'rbnacl'
require_relative 'utils'
require_relative 'builders'
require 'pry'
require 'pry-byebug'
require 'sqlite3'

include Utils
include Builders
include HKDF


# LIST OF FUNCTIONS
# the first method called to send a message to another client: computes the shared secret root key
  # e2ee_first_message
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

puts "Please provide the db password"
MASTER_KEY = prompt_password("DB password: ")
DB_FILE = File.join(Dir.pwd, "schat_db", "client1.db")
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
MSG_CLI_TO_CLI_FIRST_MESSAGE = "\x0f"
MSG_CLIENT_E2EE_ASK_MESSAGES = "\x0d"
MSG_SERVER_E2EE_DELIVER_MESSAGES = "\x0e"
MSG_CLI_TO_CLI_SUBSEQUENT_MESSAGE = "\x10"
class ProtocolError < StandardError; end

class SecureClient

  def connect
    sock = TCPSocket.new(@host, @port)
    sock
  rescue Errno::ECONNREFUSED,
    Errno::EHOSTUNREACH,
    Errno::ETIMEDOUT,
    SocketError => e
    puts "❌ Server unavailable (#{e.message})"
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
      when "\x0e"
      response = e2ee_read_server_messages_blob(handled_message, handshake_info)
    else
      raise ProtocolError, "Unknown message id: #{id.unpack1('H*')}"
    end
  response
  rescue => e
    raise
  end


  # obtain user input for a message, accepts multiple lines
  def user_message
    puts "Enter your message. Finish with an empty line or Ctrl-D:"

    lines = []

    while (line = STDIN.gets)
      line.chomp!
    break if line.empty?
      lines << line
    end

    raw_message = lines.join("\n")
    safe_terminal_print(raw_message)
  rescue => e
    raise  
  end


  # in case a message arrives that has an index higher than the expected one, we store 
  # for later reference the keys to decipher the old messages
  def store_skipped_keys(session_id, key, counter, nonce)
    db = open_db(DB_FILE)

    begin
      keys_blob = db.get_first_value(<<~SQL,
        SELECT  skipped_keys
        FROM sessions
        WHERE id = ?
      SQL
      session_id
      )

      counter_packed = [counter].pack("N")
    
      if keys_blob == nil
        keys_blob = key + counter_packed
      else
        keys_blob = keys_blob + key + counter_packed + nonce
      end   
      
      db.execute(<<~SQL,
        UPDATE sessions
        SET skipped_keys = ?
        WHERE id = ?
      SQL
      [keys_blob, session_id]
      )

    rescue
      raise ProtocolErro, "Something wrong happened during db operation"
    end
  rescue => e
    raise
  ensure
    db&.close
  end


  # in case we obtain a message that was supposed to arrive earlier, we still can decipher it
  # thanks to the previously saved message keys
  def decipher_old_messages(counter, session_id, ciphertext, remote_id, recv_index)
    db = open_db(DB_FILE)
    
    begin
      keys_blob = db.get_first_value(<<~SQL,
        SELECT skipped_keys
        FROM sessions
        WHERE id = ? 
      SQL
      session_id
      )

    rescue
      raise ProtocolError, "Something Wrong happened during db operations"
    end
    
    unless keys_blob.bytesize % 50 == 0
      raise ProtocolError "Something wrong happened during keys recovery, some might be lost for good"
    end  

    total_keys = keys_blob.bytesize / 50

    # p is used to obtain the right position for each blob is 50 bytes: 32 key, 4 index key, 24 nonce to decipher 
    total_keys.times do |i|
      p = i * (32 + 4 + 24) 
      index = keys_blob[p+32..p+35]

      if index.unpack1("N") == counter
        message_key = keys_blob[p+0..p+31]
        nonce = keys_blob[p+36..p+49]
        break

      end
    end

    secret_root_box = RbNaCl::SecretBox.new(message_key)
    plain_text = secret_root_box.open(nonce, ciphertext)

    #how do I fix that this message is out of place? Should I add a time and date from the sender side? 
    # maybe from server side?
    begin
      db.execute(<<~SQL,
        INSERT INTO messages (sender_id, message, counter)
        VALUES (?, ?, ?)
      SQL
      [previous_session["remote_id"], plain_text, counter]
      )
    rescue
      raise ProtocolError, "Something Wrong happened during db operations"
    end
  rescue => e  
    raise
  ensure
    db&.close
  end


  # recieve messages for an already established session
  def e2ee_recieve_established_sessions(remaining_message, username)

    offset = 0
    
    nonce_size_header = read_exact(remaining_message, offset, 2)
    nonce_size = nonce_size_header.unpack1("n")
    offset += 2

    ciphertext_size_header = read_exact(remaining_message, offset, 4)
    ciphertext_size = ciphertext_size_header.unpack1("N")
    offset += 4

    counter_header = read_exact(remaining_message, offset, 4)
    counter = counter_header.unpack1("N")
    offset += 4

    raise ProtocolError, "Mismatch between declared size and received message" unless remaining_message.bytesize == 2 + 4 + 4 + nonce_size + ciphertext_size

    nonce = read_exact(remaining_message, offset, nonce_size)
    offset += nonce_size
    
    ciphertext = read_exact(remaining_message, offset, ciphertext_size)

    db = open_db(DB_FILE)

    begin 
      previous_session = db.get_first_row(<<~SQL,
        SELECT * FROM sessions
        WHERE remote_id = (SELECT id FROM clients_info WHERE username = ?)
        SQL
        username.force_encoding("UTF-8")
      )
      id_pub_keys = db.execute(<<~SQL,
        SELECT user.identity_public_key AS local, cli.identity_public_key AS remote
        FROM user JOIN clients_info cli
        WHERE cli.id = ?
        SQL
        previous_session["remote_id"]
      )

    rescue
      raise ProtocolError, "Something wrong happened during db operations"
    end

    local_id_pub_key = id_pub_keys[0]["local"]
    remote_id_pub_key = id_pub_keys[0]["remote"]

    if local_id_pub_key < remote_id_pub_key
      send_dir = :a_to_b
      recv_dir = :b_to_a
    else
      send_dir = :b_to_a
      recv_dir = :a_to_b
    end

    recv_chain_key = previous_session["#{recv_dir}_chain_key"]
    recv_index = previous_session["#{recv_dir}_index"]

    show_chat(username)
    puts "New messages:"

    if counter > recv_index
      difference = counter - recv_index

      puts "A number of message(s) is lost in action: #{difference}"
      puts "Deciphering the message we received in the meantime"
      puts "If the older messages will arrive will be deciphered with "
      raise "Too many skipped messages" if difference > 200

      difference.times do |i|
        message_key = RbNaCl::HMAC::SHA256.new(recv_chain_key).auth("MESSAGE".b)
        recv_chain_key = RbNaCl::HMAC::SHA256.new(recv_chain_key).auth("CHAIN".b)

        store_skipped_keys(previous_session["id"], message_key, recv_index + i, nonce)
      end

    elsif counter < recv_index
      decipher_old_messages(counter, previous_session["id"], ciphertext, previous_session["remote_id"], recv_index)    
    end

    message_key = RbNaCl::HMAC::SHA256.new(recv_chain_key).auth("MESSAGE".b)
    secret_root_box = RbNaCl::SecretBox.new(message_key)
    next_recv_chain_key = RbNaCl::HMAC::SHA256.new(recv_chain_key).auth("CHAIN".b)
    recv_index += 1

    plain_text = secret_root_box.open(nonce, ciphertext)
    db.transaction do
      db.execute(<<~SQL,
        INSERT INTO messages (sender_id, message, counter)
        VALUES (?, ?, ?)
      SQL
      [previous_session["remote_id"], plain_text, recv_index - 1]
      )
      
      r_key = "#{recv_dir}_chain_key"
      r_index = "#{recv_dir}_index"
      db.execute(<<~SQL,
        UPDATE sessions
        SET #{r_key} = ?, #{r_index} = ?
        WHERE id = ?
      SQL
      [next_recv_chain_key, recv_index, previous_session["remote_id"]]
      )
    end  
  rescue => e
    raise  
  ensure
    db&.close  
  end

  
  # continue a previously started chat (send a message)
  def e2ee_continue_chat(username, handshake_info, nonce_session)
    db = open_db(DB_FILE)

    begin
      previous_session = db.get_first_row(<<~SQL,
        SELECT * FROM sessions
        WHERE remote_id = (SELECT id FROM clients_info WHERE username = ?)
        SQL
        username.force_encoding("UTF-8")
      )
      id_pub_keys = db.execute(<<~SQL,
        SELECT user.identity_public_key AS local, cli.identity_public_key AS remote 
        FROM user JOIN clients_info cli 
        WHERE cli.id = ?
        SQL
        previous_session["remote_id"]
      )
    rescue
      raise "Couldn't fetch previous sessions details"
    end

    local_id_pub_key = id_pub_keys[0]["local"]
    remote_id_pub_key = id_pub_keys[0]["remote"]

    if local_id_pub_key < remote_id_pub_key
      send_dir = :a_to_b
      recv_dir = :b_to_a
    else
      send_dir = :b_to_a
      recv_dir = :a_to_b
    end
    send_chain_key = previous_session["#{send_dir}_chain_key"]
    send_index = previous_session["#{send_dir}_index"]

    message_key = RbNaCl::HMAC::SHA256.new(send_chain_key).auth("MESSAGE".b)
    secret_root_box = RbNaCl::SecretBox.new(message_key)
    next_send_chain_key = RbNaCl::HMAC::SHA256.new(send_chain_key).auth("CHAIN".b)

    nonce = RbNaCl::Random.random_bytes(secret_root_box.nonce_bytes)
    nonce_size = [nonce.bytesize].pack("n")
    message = user_message()

    ciphertext = secret_root_box.box(nonce, message)
    ciphertext_size = [ciphertext.bytesize].pack("N")

    counter = [send_index].pack("N")

    payload =
      MSG_CLI_TO_CLI_SUBSEQUENT_MESSAGE +
      nonce_size +
      ciphertext_size +
      counter +
        nonce +
      ciphertext
     
    send_index += 1
    
    username_size = [username.bytesize].pack("C")
    payload_size = [payload.bytesize].pack("N")
    
    message = 
      MSG_CLIENT_E2EE_FIRST_MESSAGE +
      username_size +
      payload_size +
      username +
      payload
      
    message_sliced = message.byteslice(1..)
    digest = RbNaCl::Hash.sha256(message_sliced)
    server_answer = finalizer(nonce_session, handshake_info, message)
    puts "as"
    if server_answer == digest 
      puts "Message properly uploaded"   

      begin
        db.transaction do
          s_key = "#{send_dir}_chain_key"
          s_index = "#{send_dir}_index"
          db.execute(<<~SQL,
            UPDATE sessions 
            SET #{s_key} = ?, #{s_index} = ?
            WHERE id = ?
          SQL
          [next_send_chain_key, send_index, previous_session["id"]]
          )
        end
      rescue
        raise ProtocolError, "Something wrong happened during db operation"
      end  
    end  
  rescue => e
    raise  
  ensure
    db&.close
  end


  # parses a header flag, so far tells if there is already an e2ee session among the peers
  # tells the peer that there actually already is such a session
  def e2ee_client_message_parser(message, username)
    db = open_db(DB_FILE)

    flag = read_exact(message, 0, 1)
    remaining_message = message.byteslice(1..)
      session = db.get_first_value(<<-SQL,
        SELECT id FROM sessions WHERE remote_id = (
          SELECT id FROM clients_info WHERE username = ?)
        SQL
        username.force_encoding("UTF-8")
      )
    case flag
    when "\x0f"
      if session == nil
        e2ee_peer_first_message(remaining_message, username)
      else
        raise ProtocolError, "There is already an active session among the users, but the remote asks for a fresh session"
      end  
    when "\x10"
      if session == nil
        raise ProtocolError, "There is no active session among the users, but the remot user asks to continue a pre established one"
      else
        e2ee_recieve_established_sessions(remaining_message, username)    
      end
    end
  rescue => e
    raise  
  ensure
    db&.close    
  end


  # reads all the messages sent from the server
  # sees how many messages are in the queue, who is the sender 
  # checks if this is a new or old communication session
  def e2ee_read_server_messages_blob(handled_payload, handled_client)
    offset = 0
    messages_count_header = read_exact(handled_payload, offset, 2)
    messages_count = messages_count_header.unpack1("n")
    offset += 2
    messages_count.times do
      username_size_header = read_exact(handled_payload, offset, 1)
      username_size = username_size_header.unpack1("C")
      offset += 1

      message_size_header = read_exact(handled_payload, offset, 4)
      message_size = message_size_header.unpack1("N")
      offset += 4

      username = read_exact(handled_payload, offset, username_size)
      offset += username_size
      
      message = read_exact(handled_payload, offset, message_size)
      offset += message_size
      e2ee_client_message_parser(message, username)    
    end
  rescue => e
    raise  
  end


  def keys_and_index(keys, root_key, local_id_pub_key, remote_id_pub_key)

    a_to_b_chain_key = HKDF.expand(root_key, "CHAIN-A-TO-B".b, 32)
    b_to_a_chain_key = HKDF.expand(root_key, "CHAIN-B-TO-A".b, 32)

    session = {
      a_to_b_chain_key: a_to_b_chain_key,
      a_to_b_index: 0,
      b_to_a_chain_key: b_to_a_chain_key,
      b_to_a_index: 0
    }

    if local_id_pub_key < remote_id_pub_key
      send_dir = :a_to_b
      recv_dir = :b_to_a
    else
      send_dir = :b_to_a
      recv_dir = :a_to_b
    end

    def chain_key_for(session, direction)
      session[:"#{direction}_chain_key"]
    end

    def index_for(session, direction)
      session[:"#{direction}_index"]
    end

    send_chain_key = chain_key_for(session, send_dir)
    recv_chain_key = chain_key_for(session, recv_dir)
    send_index = index_for(session, send_dir)
    recv_index = index_for(session, recv_dir)

    role = {send_dir: send_dir, recv_dir: recv_dir, send_key: send_chain_key, recv_key: recv_chain_key, send_index: send_index, recv_index: recv_index}
    role
  rescue => e
    raise  
  end

  
  # ask the server if there's messages in the queue and fetch them
  def e2ee_ask_messages(handshake_info, nonce_session)

    message = MSG_CLIENT_E2EE_ASK_MESSAGES

    server_answer = finalizer(nonce_session, handshake_info, message)
    handler_caller(server_answer)
  rescue => e
    raise  
  end


  # receive the first message from a different client
  def e2ee_peer_first_message(message, username)
    offset = 0
    remote_id_pub_key = read_exact(message, offset, 32)
    offset += 32

    remote_signing_pub_key = read_exact(message, offset, 32)
    offset += 32

    remote_eph_pub_key = read_exact(message, offset, 32)
    offset += 32

    local_ot_pub_key_used = read_exact(message, offset, 32)
    offset += 32

    local_signed_pub_key_used = read_exact(message, offset, 32)
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

    unless message.bytesize == ciphertext_size + nonce_size + signature_size + (32 * 5) + 2 + 2 + 4 + 4
      raise ProtocolError, "Declared and received size mismatch"
    end    

    counter = read_exact(message, offset, 4).unpack1("N")
    raise ProtocolError, "counter size too big" unless counter == 0
    offset += 4
    
    signature = read_exact(message, offset, signature_size)
    offset += signature_size

    remote_signing_pub_key_prepared = RbNaCl::Signatures::Ed25519::VerifyKey.new(remote_signing_pub_key)
    transcript = remote_id_pub_key + remote_eph_pub_key
    
    unless remote_signing_pub_key_prepared.verify(signature, transcript)
      raise ProtocolError, "remote signed key is not verified"
    end
    nonce = read_exact(message, offset, nonce_size)
    offset += nonce_size

    ciphertext = read_exact(message, offset, ciphertext_size)

    db = open_db(DB_FILE)

    begin
      keys = db.get_first_row(<<-SQL,
        SELECT pre.private_signed_prekey AS signed, 
          user.identity_public_key AS id_pub , 
          user.identity_private_key AS id_pri,
          otp.one_time_private_key AS ot
        FROM shared_prekey pre
        JOIN user 
        JOIN one_time_prekeys otp
        WHERE pre.public_signed_prekey = ?
        AND otp.one_time_public_key = ?
      SQL
      [local_signed_pub_key_used, local_ot_pub_key_used]
      )
    rescue
      raise ProtocolError, "Something went wrong during db interaction"
    end
    raise "Missing keys" unless keys

    local_signed_pri_key = keys["signed"]
    local_id_pri_key = keys["id_pri"]
    local_id_pub_key = keys["id_pub"]
    local_ot_pri_key = keys["ot"]

    dh1 = dh(local_signed_pri_key, remote_id_pub_key)
    dh2 = dh(local_id_pri_key, remote_eph_pub_key)
    dh3 = dh(local_signed_pri_key, remote_eph_pub_key)
    dh4 = dh(local_ot_pri_key, remote_eph_pub_key)

    combined_secrets = dh1+dh2+dh3+dh4
    root_key = HKDF.extract(combined_secrets)

    elements = keys_and_index(keys, root_key, local_id_pub_key, remote_id_pub_key)
    send_dir = elements[:send_dir]
    recv_dir = elements[:recv_dir]
    send_chain_key = elements[:send_key]
    recv_chain_key = elements[:recv_key]
    send_index = elements[:send_index]
    recv_index = elements[:recv_index]

    message_key = RbNaCl::HMAC::SHA256.new(recv_chain_key).auth("MESSAGE".b)
    secret_root_box = RbNaCl::SecretBox.new(message_key)
    next_recv_chain_key = RbNaCl::HMAC::SHA256.new(recv_chain_key).auth("CHAIN".b)

    recv_index += 1
    send_index = 0
    plain_text = secret_root_box.open(nonce, ciphertext)
    begin
      db.transaction do
        local_id = db.get_first_value("SELECT id FROM user")
        username_id = db.execute(<<~SQL,
          INSERT INTO clients_info (username, signing_public_key, identity_public_key, signed_prekey_sig)
          VALUES (?, ?, ?, ?)
          RETURNING id
        SQL
        [username.force_encoding("UTF-8"), remote_signing_pub_key, remote_id_pub_key, signature]
        )
        db.execute(<<~SQL,
          INSERT INTO messages (sender_id, message, counter) 
          VALUES (?, ?, ?)
        SQL
        [username_id[0]["id"], plain_text, recv_index - 1]        
        )

        s_key   = "#{send_dir}_chain_key"
        s_index = "#{send_dir}_index"
        r_key   = "#{recv_dir}_chain_key"
        r_index = "#{recv_dir}_index"
        db.execute(<<~SQL,
          INSERT INTO sessions
          (local_id, remote_id, root_key, #{s_key}, #{s_index}, #{r_key}, #{r_index})
          VALUES (?, ?, ?, ?, ?, ?, ?)
        SQL
        [local_id, username_id[0]["id"], root_key, send_chain_key, send_index, recv_chain_key, recv_index]
        )
        db.execute(<<~SQL,
          DELETE FROM one_time_prekeys 
          WHERE one_time_public_key = ?
        SQL
        local_ot_pub_key_used  
        )
      end
    rescue
      raise ProtocolError, "Coulnd't save the user message on the local db"
    end
    show_chat(username)
  rescue => e
    raise  
  ensure
    db&.close
  end


  # the first method called to send a message to another client: derives the root key
  def e2ee_first_message(handshake_info, nonce_session)
    puts "Please provide the username you wish to interact with"
    username = STDIN.gets.strip
    raise ArgumentError, "Wrong username format" unless username.match?(/\A[A-Za-z0-9]{5,20}\z/)
    db = open_db(DB_FILE)

    existing_session_id = db.get_first_value(<<~SQL,
      SELECT id FROM sessions WHERE (SELECT id FROM clients_info WHERE username = ?)
    SQL
    username.force_encoding("UTF-8")
    )

    if existing_session_id
      puts "A session with this user already exists exiting"
      e2ee_continue_chat(username, handshake_info, nonce_session)
      return 0
    end

    ephemeral_sk = RbNaCl::PrivateKey.generate
    ephemeral_pk = ephemeral_sk.public_key

    ephemeral_sk_bytes = ephemeral_sk.to_bytes
    ephemeral_pk_bytes = ephemeral_pk.to_bytes
       
    begin

      client_info = db.get_first_row("SELECT * FROM clients_info WHERE username = ?", [username])      
      raise "No username found with name #{username}" unless client_info
      remote_signing_pub_key = client_info["signing_public_key"]
      remote_id_pub_key = client_info["identity_public_key"]
      remote_signed_pub_key = client_info["signed_prekey_pub"]
      remote_ot_pub_key = client_info["one_time_key"]
      keys = db.get_first_row("SELECT identity_private_key AS priv, identity_public_key AS pub FROM user")

      raise "Missing keys" unless keys

      local_identity_pub_key = keys["pub"]
      local_identity_pri_key = keys["priv"]

      dh1 = dh(local_identity_pri_key, remote_signed_pub_key)
      dh2 = dh(ephemeral_sk_bytes, remote_id_pub_key)
      dh3 = dh(ephemeral_sk_bytes, remote_signed_pub_key)
      dh4 = dh(ephemeral_sk_bytes, remote_ot_pub_key)

      combined_secrets = dh1+dh2+dh3+dh4
      root_key = HKDF.extract(combined_secrets)

      elements = keys_and_index(keys, root_key, local_identity_pub_key, remote_id_pub_key)

      send_dir = elements[:send_dir]
      recv_dir = elements[:recv_dir]
      send_chain_key = elements[:send_key]
      recv_chain_key = elements[:recv_key]
      send_index = elements[:send_index]
      recv_index = elements[:recv_index]
      message_key = RbNaCl::HMAC::SHA256.new(send_chain_key).auth("MESSAGE".b)
      secret_root_box = RbNaCl::SecretBox.new(message_key)
      next_send_chain_key = RbNaCl::HMAC::SHA256.new(send_chain_key).auth("CHAIN".b)
    rescue
      raise ProtocolError, "Something wrong happened with the shared secrets creation."
    end

    nonce = RbNaCl::Random.random_bytes(secret_root_box.nonce_bytes)
    nonce_size = [nonce.bytesize].pack("n")
    message = user_message()
    
    ciphertext = secret_root_box.box(nonce, message)
    ciphertext_size = [ciphertext.bytesize].pack("N")

    transcript = local_identity_pub_key + ephemeral_pk_bytes
    
    signature = @host_sk.sign(transcript)
    signature_size = [signature.bytesize].pack("n")
    counter = [send_index].pack("N")
    payload =
      MSG_CLI_TO_CLI_FIRST_MESSAGE +
      local_identity_pub_key +
      @host_pk.to_bytes +
      ephemeral_pk_bytes +
      remote_ot_pub_key +
      remote_signed_pub_key +
      signature_size +
      nonce_size +
      ciphertext_size +
      counter +
      signature +
      nonce +
      ciphertext

    send_index += 1  

    username_size = [username.bytesize].pack("C")
    payload_size = [payload.bytesize].pack("N")

    message = 
      MSG_CLIENT_E2EE_FIRST_MESSAGE +
      username_size +
      payload_size +
      username +
      payload

    server_answer = finalizer(nonce_session, handshake_info, message)

    message_sliced = message.byteslice(1..)
    digest = RbNaCl::Hash.sha256(message_sliced)

    if server_answer == digest
    puts "Message properly uploaded"
    
      begin
        db.transaction do
        local_id = db.get_first_value("SELECT id FROM user")
        remote_id = db.get_first_value("SELECT id FROM clients_info WHERE username = ?", username.force_encoding("UTF-8"))
        s_key   = "#{send_dir}_chain_key"
        s_index = "#{send_dir}_index"
        r_key   = "#{recv_dir}_chain_key"
        r_index = "#{recv_dir}_index"
        db.execute(
          <<~SQL,
            INSERT INTO sessions
            (local_id, remote_id, root_key, #{s_key}, #{s_index}, #{r_key}, #{r_index})  
            VALUES (?, ?, ?, ?, ?, ?, ?)
          SQL
          [local_id, remote_id, root_key, next_send_chain_key, send_index, recv_chain_key, recv_index]
        )

        end
      rescue
        raise ProtocolError, "Something went wrong during db operations"
      end
    end
  rescue => e
    raise  
  ensure
    db&.close
  end

  
  # wrapper around the receiver for the e2ee material 
  def e2ee_client_share_receiver_wrapper(payload, handshake_info)
    e_material = e2ee_keys_share_receiver(payload, handshake_info)
    username = e_material[:username].force_encoding("UTF-8")
    signing_pub_key = e_material[:signing_pub_key]
    identity_pub_key = e_material[:identity_pub_key]
    signed_pk = e_material[:signed_pk]
    signature = e_material[:signature]
    one_time_keys = e_material[:otpk]
    otp_amount = e_material[:otp_amount]

    db = open_db(DB_FILE)

    raise ProtocolError, "Too many one time keys" unless otp_amount == 1 && one_time_keys.bytesize == 33
    
    otp = read_exact(one_time_keys, 0, 32)
    counter_packed = read_exact(one_time_keys, 32, 1)
    counter = counter_packed.unpack1("C")
    begin
      db.transaction do
      db.execute(
          <<~SQL,
            INSERT INTO clients_info (username, signing_public_key, identity_public_key, signed_prekey_pub, signed_prekey_sig, one_time_key) 
            VALUES (?, ?, ?, ?, ?, ?)
          SQL
          [username, signing_pub_key, identity_pub_key, signed_pk, signature, otp]
        )
      end
    rescue SQLite3::ConstraintException
      raise ProtocolError, "client already registered"
    end
  rescue  => e
    raise   
  ensure
  db&.close
  end


  # method used to establish a connection with a given user
  def e2ee_keys_request(handshake_info, nonce_session)
    puts "Please provide the username you wish to interact with"
    username = STDIN.gets.strip    

    username_size = [username.bytesize].pack("C")

    raise ArgumentError, "Wrong username format" unless username.match?(/\A[A-Za-z0-9]{5,20}\z/)

    username_payload = 
      MSG_CLIENT_E2EE_KEYS_REQUEST + 
      username_size +
      username
    server_answer = finalizer(nonce_session, handshake_info, username_payload)
    handler_caller(server_answer)
  rescue => e
    raise  
  end


  # the hello method that asks the server to save the keys and signature, later used by other clients for e2ee
  def e2ee_keys_share(handshake_info, nonce_session)
    db = open_db(DB_FILE)

    signed_sk = RbNaCl::PrivateKey.generate
    signed_pk = signed_sk.public_key

    signed_sk_bytes = signed_sk.to_bytes
    signed_pk_bytes = signed_pk.to_bytes

    begin
      host_id_pub_key = db.get_first_value("SELECT identity_public_key FROM user")
      db.execute("INSERT INTO shared_prekey (private_signed_prekey, public_signed_prekey) VALUES (?, ?)",
      [signed_sk_bytes, signed_pk_bytes]
      )

    rescue
      raise ArgumentError, "Local public_id_key not found"
    end

    transcript = host_id_pub_key + signed_pk_bytes

    signed_prekeys_sig = @host_sk.sign(transcript)

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
    begin
      host_id_pub_key = db.get_first_value("SELECT identity_public_key FROM user")
    rescue
      raise ArgumentError, "Local public_id_key not found"
    end
    payload = e2ee_builder(username, @host_pk.to_bytes, host_id_pub_key, signed_pk_bytes, signed_prekeys_sig,  one_time_prekeys, 49)

    message = MSG_CLIENT_E2EE_KEYS_SHARE + payload
    server_return = finalizer(nonce_session, handshake_info, message)    

    digest = RbNaCl::Hash.sha256(payload)
    raise ProtocolError, "Server payload digest mismatch" unless digest == server_return
    puts "Keys shared with success" if digest == server_return    
  rescue => e
    raise
  ensure
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
  rescue => e
    raise  
  end

  # ask the user to provide a valid voucher and also recover the nickname from the db,
  def registration_request(handshake_info, nonce_session)
    db = open_db(DB_FILE)

    # obtain the nickname from the db
    nickname = db.get_first_value(<<-SQL)
      SELECT username FROM user;
    SQL

    raise ArgumentError, "Please register a username first during database setup" unless nickname 

    # obtain the voucher
    puts "Insert a valid voucher:"
    while true
      input = STDIN.gets.strip
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

    server_return = finalizer(nonce_session, handshake_info, registration_data)
    handler_caller(server_return)
  rescue => e
    raise  
  ensure
    db&.close  
  end


  # method called to handle the last phase of each method, sends packet and returns the deciphered answer
  def finalizer(nonce_session, handshake_info, message)
    sock = handshake_info[:sock]
    safe_box = handshake_info[:client_box]

    sender(sock, safe_box, nonce_session, message)
    returned_payload = read_blob(sock)
    plain_text = decipher(returned_payload, safe_box)
    plain_text    
  rescue => e
    raise  
  end


  # called during hello_client to check if the public key matches the registered server
  def server_fingerprint_check(remote_pk)
    db = open_db(DB_FILE)

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
  rescue => e
    raise
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
    sock = connect()
    return unless sock 
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
  rescue => e
    raise
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

    db = open_db(DB_FILE)

    hex = fingerprint.delete(":")
    pk_bytes = [hex].pack("H*")

    raise ArgumentError, "Invalid public key length" unless pk_bytes.bytesize == 32

    db.execute("INSERT INTO server_identity (fingerprint, server_name, public_key) VALUES (?, ?, ?)",
      [fingerprint, server_name, pk_bytes]
    )
  rescue => e
    raise  
  ensure
    db&.close
  end


  # the initialization method
  def initialize(host, port)
    @host, @port = host, port

    db = open_db(DB_FILE)

    host_row = db.get_first_row("SELECT signing_private_key, signing_public_key FROM user")

    raise ProtocolError, "No host key found" unless host_row

    # Long-term host signing key (Ed25519)
    host_sk_bytes = host_row["signing_private_key"]
    host_pk_bytes = host_row["signing_public_key"]

    @host_sk = RbNaCl::Signatures::Ed25519::SigningKey.new(host_sk_bytes)
    @host_pk = RbNaCl::Signatures::Ed25519::VerifyKey.new(host_pk_bytes)
  rescue => e
    raise  
  ensure
    db&.close
  end

# end of the client class  
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

  db = open_db(DB_FILE)

  hex = fingerprint.delete(":")
  pk_bytes = [hex].pack("H*")

  raise ArgumentError, "Invalid public key length" unless pk_bytes.bytesize == 32

  db.execute("INSERT INTO server_identity (fingerprint, server_name, public_key) VALUES (?, ?, ?)",
    [fingerprint, server_name, pk_bytes]
  )
rescue => e
  raise  
ensure
  db&.close
end


# prints on screen the messages on the db
def show_chat(username)
  db = open_db(DB_FILE)

  messages = []
  begin
    db.transaction do
      previous_session = db.get_first_row(<<~SQL,
        SELECT * FROM sessions
        WHERE remote_id = (SELECT id FROM clients_info WHERE username = ?)
        SQL
        username.force_encoding("UTF-8")
      )
      messages = db.execute(<<~SQL,
        SELECT * FROM messages
        WHERE sender_id = (SELECT id FROM clients_info WHERE username = ?)
        ORDER by counter ASC
        SQL
        username.force_encoding("UTF-8")
        )
    end
  rescue
    raise ProtocolError, "Some db operation didn't work out"
  end
  puts "#{username}:"
  messages.each do |msg|
    puts "msg id counter: #{msg["counter"]}"
    puts safe_terminal_print(msg["message"])
    puts "-" * 40
  end
rescue => e
  raise  
ensure
  db&.close
end


# show the currents users in the clients info db
def show_users()
  db = open_db(DB_FILE)

  users = db.execute("SELECT username FROM clients_info")

  users.each do |u| puts safe_terminal_print(u["username"]) end
rescue => e  
  raise
ensure
  db&.close
end


# cleans a message from potential injection characters
def safe_terminal_print(str)
  str
    .encode("UTF-8", invalid: :replace, undef: :replace, replace: "�")
    .gsub(/[\u202A-\u202E\u2066-\u2069]/, "")   # bidi controls
    .gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/, "")
rescue => e
  raise
end


# to handle the client shutdown
def shutdown(handshake_info, db, exit_code: 0)
  puts "\nShutting down…"

  unless handshake_info.nil?
    socket = handshake_info[:sock]
    begin
      socket.close unless socket.closed?
    rescue => e
      warn "Socket close failed: #{e.message}"
    end
  end

  # Close database
  unless db.nil?
    begin
      db.execute("PRAGMA cipher_memory_security = ON")
      db.close
    rescue => e
      warn "DB close failed: #{e.message}"
    end
  end

  # Best-effort memory cleanup
  GC.start

  exit(exit_code)
end



def main

handshake_info = nil
nonce_session = nil
  if !File.exist?(DB_FILE)
    puts "Please run the client_setup.rb file first"
    exit
  end  

  puts "Please provide the db password"
  
  db = open_db(DB_FILE)
  puts "Schat. SecureChat client v1.0"

  server_id = db.execute("SELECT id FROM server_identity")
  if server_id.empty? == true
    server_fingerprint_registration()
  end

  
  
  loop do
  puts "\n"
  puts "Choose an option:"
  puts "1) register server fingerprint on the local db"
  puts "2) register the client with the server"
  puts "3) manually share with the server the keys for e2ee"
  puts "4) obtain the keys for e2ee for a given username"
  puts "5) Starts communication with a given username"
  puts "6) Fetch messages on the server"
  puts "7) Continue a previosly started chat"
  puts "8) Show messages received from a given user"
  puts "9) show users to interact with"
  puts "11) to close"
  choice = STDIN.gets.strip.to_i
  
  if choice == 1 || choice == 8 || choice == 9 || choice == 11
    case choice
    when 1
      # - used to register a server with a previously shared public key / fingerprint
      server_fingerprint_registration()
    when 8
      loop do
        puts "Choose a username to interact with"
        username = STDIN.gets.strip
        raise ArgumentError, "No input provided" if username.nil?

        if  username.match?(/\A[A-Za-z0-9]{5,20}\z/)
          show_chat(username)
          break
        end
      end
    when 9
      show_users()
    when 11
      shutdown(handshake_info, db)
    end
    next
  end
  
  unless handshake_info && nonce_session
    client = SecureClient.new("127.0.0.1", 2222)
    handshake_info = client.hello_server()
    nonce_session = Session.new("server", handshake_info[:client_nonce])
  end


  case choice
    when 1
      # - used to register a server with a previously shared public key / fingerprint
      server_fingerprint_registration()
      
    when 2
      # -inside handshake info there is all the info concerning the connection:
      # - used to ask the server to register our client nickname and voucher
      client.registration_request(handshake_info, nonce_session)

    when 3
      client.e2ee_keys_share(handshake_info, nonce_session)

    when 4
      client.e2ee_keys_request(handshake_info, nonce_session)        

    when 5
      client.e2ee_first_message(handshake_info, nonce_session)

    when 6
      client.e2ee_ask_messages(handshake_info, nonce_session)        

    when 7
      loop do
        puts "Choose a username to interact with"

        username = STDIN.gets.strip
        raise ArgumentError, "No input provided" if username.nil?

        if  username.match?(/\A[A-Za-z0-9]{5,20}\z/)
          username_id = db.get_first_value(<<~SQL,
          SELECT username from clients_info WHERE username = ?
          SQL
          username
          )
          
          if username_id
            client.e2ee_continue_chat(username, handshake_info, nonce_session)
            break
                        
          else
            puts "No existing user with username: #{username}"
            next
          end
        else
          puts "Invalid username format only alphanumerical and 0-9, 5 to 20 characters"
          next
        end     
      end
    when 8
      loop do
        puts "Choose a username to interact with"
        username = STDIN.gets.strip
        raise ArgumentError, "No input provided" if username.nil?

        if  username.match?(/\A[A-Za-z0-9]{5,20}\z/)
          show_chat(username)
          break
        end
      end
    when 9
      show_users()
    when 10
      puts "secret easter egg, love you all!"
    when 11
      shutdown(handshake_info, db)
  else
    puts "non existing choice"
    next
  end

  # this end is for the loop
  end
ensure
  db&.close  
end
  
main

