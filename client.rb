require 'socket'
require 'rbnacl'
require 'openssl'
require 'securerandom'
require_relative 'utils'

class SecureClient
  def initialize(host, port)
    @host, @port = host, port
  end

  def send_message(msg)
    sock = TCPSocket.new(@host, @port)

    # 1) Ephemeral client key
    eph_sk = RbNaCl::PrivateKey.generate
    eph_pk = eph_sk.public_key

    # 2) Receive host pub, server eph pub, signature
    host_pk = RbNaCl::VerifyKey.new(read_blob(sock))
    server_eph_pk = read_blob(sock)
    sig = read_blob(sock)

    # Verify signature
    host_pk.verify(sig, server_eph_pk)

    server_eph_pk = RbNaCl::PublicKey.new(server_eph_pk)

    # 3) Shared secret
    shared_secret = eph_sk.exchange(server_eph_pk)

    # 4) Derive keys
    key_material = OpenSSL::KDF.hkdf(shared_secret, salt: "", info: "ssh-like", length: 64, hash: "SHA256")
    enc_key = key_material[0,32]
    mac_key = key_material[32,32]

    # 5) Encrypt
    nonce = SecureRandom.random_bytes(16)
    cipher = OpenSSL::Cipher.new("aes-256-ctr")
    cipher.encrypt
    cipher.key = enc_key
    cipher.iv  = nonce
    ciphertext = cipher.update(msg) + cipher.final

    mac = OpenSSL::HMAC.digest("SHA256", mac_key, nonce + ciphertext)

    # 6) Send client eph pub, nonce, ciphertext, mac
    send_blob(sock, eph_pk.to_bytes)
    send_blob(sock, nonce)
    send_blob(sock, ciphertext)
    send_blob(sock, mac)

    puts "Server says: #{sock.read}"
    sock.close
  end

  def read_blob(sock)
    len = sock.read(4).unpack1("N")
    sock.read(len)
  end

  def send_blob(sock, data)
    sock.write([data.bytesize].pack("N") + data)
  end
end

client = SecureClient.new("127.0.0.1", 2222)
print "Message: "
msg = STDIN.gets.strip
client.send_message(msg)
