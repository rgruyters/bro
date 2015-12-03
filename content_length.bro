#
# Bro script for capturing incomplete bodylength

module BodyLength;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ts:           time &log;
    fuid:         string &log;
    orig_h:       addr &log;
    total_bytes:  count &log;
    seen_bytes:   count &log;
    duration:     interval &log &optional;
  };

}

event bro_init()
{
  Log::create_stream(LOG, [$columns=Info, $path="bodylength"]);
}

event file_state_remove(f: fa_file)
{
  local now = network_time();
  local c: connection;

  if ( f$info$source == "HTTP" )
  {

    if ( ! f?$total_bytes || f$total_bytes != f$seen_bytes )
    {

      for ( cid in f$conns )
      {
        c = f$conns[cid];
        break;
      }

      local info: Info = [$ts=now,
                          $fuid=f$info$fuid,
                          $orig_h=c$id$resp_h,
                          $total_bytes=f$total_bytes,
                          $seen_bytes=f$seen_bytes,
                          $duration=c$duration];

      Log::write(LOG, info);
    }

  }

}

