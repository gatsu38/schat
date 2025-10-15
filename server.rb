require 'ed25519'
require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require 'concurrent-ruby'
require_relative 'utils'
require 'pry'
require 'pry-byebug'


# used for error handling
class BlobReadError < StandardError; end
class BlobSizeError < BlobReadError; end

# === Server ===
class SecureServer
  include Utils

  # handles a single client 
  def handle_client(sock)
    puts "handle client"
    # Ephemeral X25519 server key pair, one pair per client
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key
    # Sign ephemeral pub with host key, creates a signature
    sig = @host_sk.sign(eph_pk.to_s)

    # !!!! ERROR HAS TO BE FOR EACH MESSAGE ONLY FOR TEST create a nonce for the session
    nonce = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
    
    puts "start kex sending"
    # Send public signing key and ephemeral key (kex)
    send_kex(sock, @host_pk, eph_pk, sig, nonce)
    # confirm kex has been sent
    # confirm_kex_arrived(sock, sig)

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
    binding.pry
    puts "aasdasdsadasdassd"
    
#    key_material = key_material_func(eph_sk, eph_pk, client_eph_pk, session_salt)
 #   enc_key = key_material[0,32]
  #  mac_key = key_material[32,32]

    # Receive nonce, ciphertext, mac and check for proper size/content value
 #   nonce = read_blob(sock)
  #  ciphertext = read_blob(sock)
  #  mac = read_blob(sock)
#    check_nonce_ciph

 #   raise "Invalid nonce length: expected 12 bytes, got #{nonce&.bytesize || 0}" unless nonce&.bytesize == 12
 #   raise "Invalid ciphertext: empty or nil" if ciphertext.nil? || ciphertext.empty?
 #   raise "Invalid MAC length: expected 32, got #{mac&.bytesize || 0}" if mac.nil? || mac.bytesize != 32

    # Verify HMAC
#    hmac = OpenSSL::HMAC.digest("SHA256", mac_key, nonce + ciphertext)
  #  if hmac != mac
  #    puts "HMAC failed!"
  #    sock.close
  #    return
  #  end

    # Decrypt AES-CTR
    # create a new cipher object
   # cipher = OpenSSL::Cipher.new("aes-256-ctr")
    # sets cipher to decryption mode
  #  cipher.decrypt
    # set decryption key
  #  cipher.key = enc_key
    # set initialization vector to nonce
   # cipher.iv = nonce
    # obtain fully decrypted text
   # plaintext = cipher.update(ciphertext) + cipher.final

    #puts "Received: #{plaintext}"
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

