#
# Bro script for capturing incomplete bodylength

module BodyLength;

global src_host = 0.0.0.0 &redef;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ts:           time &log;
    orig_h:       addr &log;
    total_bytes:  count &log;
    seen_bytes:   count &log;
  };

}

event bro_init()
{
  Log::create_stream(LOG, [$columns=Info, $path="bodylength"]);
}

event file_state_remove(f: fa_file)
{
  local now = network_time();

  if ( f$info$source == "HTTP" )
  {

    if ( ! f?$total_bytes || f$total_bytes != f$seen_bytes )
    {

      for ( h in f$info$tx_hosts )
      {
        src_host = h;
      }

      local total_bytes = f$total_bytes;
      local seen_bytes = f$seen_bytes;

      local info: Info = [$ts=now,
                          $orig_h=src_host,
                          $total_bytes=total_bytes,
                          $seen_bytes=seen_bytes];

      Log::write(LOG, info);

      print fmt("%s: Wrong body size from host: %s. (%d versus %d)", strftime("%Y/%M/%d %H:%m:%S", f$http$ts), src_host, f$total_bytes, f$seen_bytes);
    }

  }

}

