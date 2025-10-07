# reading and writing functions
module utilities

  def read_blob(sock, MAX_BLOB_SIZE = 16 * 1024 * 1024, timeout: 10)
    # read header (4 bytes), waits 10 seconds before giving up
    ready = IO.select([sock], nil, nil, timeout)
    raise Timeout::Error, "Timeout waiting for length header" unless ready

    # check header's size
    header = sock.read(4)
    raise EOFError, "Connection closed while reading length header" if header.nil? || header.bytesize < 4

    # sanity check for payload length
    blob_len = header.unpack1("N")  # unpack1 gives an integer directly
    raise BlobSizeError, "Invalid blob size: #{blob_len}" if blob_len < 0 || blob_len > max_blob_size

    # read payload (exactly blob_len bytes) blob will contain the payload
    # +"" creates a new mutable empty String (not frozen). 
    blob = +""
    while blob.bytesize < blob_len
      ready = IO.select([sock], nil, nil, timeout)
      raise Timeout::Error, "Timeout while reading blob" unless ready

      chunk = sock.read(blob_len - blob.bytesize)
      raise EOFError, "Connection closed while reading blob (expected #{blob_len}, got #{blob.bytesize})" if chunk.nil? || chunk.empty?

      blob << chunk
    end

    blob
  end


  # helper method to ensure full_write
  def write_all(sock, data)
    total_written = 0
    attempts = 0 
    begin
      # tries to write as many bytes as possible and doesn't block the server
      while total_written < data.bytesize
        written = sock.write_nonblock(data[total_written..-1]
        total_written += written
      end

    # in case of failure wait untill the socket is writable, 5 maximum attempts
    rescue IO::WaitWritable
      attempts += 1
      raise IOError, "Socket not writable after 5 attempts" if attempts >= 5
      ready = IO.select(nil, [sock], nil, 5)
      retry if ready 
      raise IOError, "Socket not writable within timeout"
      
    end
  end
end
