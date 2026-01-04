# This file is a collection of methods used to build payloads

#registration_builder
  # build the registration message for the client to send to the server
# registration_response
  # build the payload for the server to answer client's registration 
# hello_back_payload_builder
  # build the hello back payload
# sig_builder
  # build the signature to send back to the client after hello
# protocol_name_builder
  # builder for client hello: protocol name + padding preparation


module Builders

  # build the registration message
  def registration_builder(nickname, voucher)
    raise ArgumentError, "Nickname too long" if nickname.bytesize > 20

    registration_payload =
      MSG_CLIENT_REGISTRATION +
      [nickname.bytesize].pack("C") +
      nickname +
      voucher

    registration_payload
  end


  # build the payload for the server to answer client's registration 
  def registration_response_builder(flag)
    response = 
      MSG_SERVER_REGISTRATION_RESPONSE +
      flag
  response
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

end

