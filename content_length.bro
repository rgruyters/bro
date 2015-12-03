#
# Bro script for capturing incomplete bodylength

global src_host = 0.0.0.0 &redef;

event file_state_remove(f: fa_file)
{

  if ( f$info$source == "HTTP" )
  {

    if ( ! f?$total_bytes || f$total_bytes != f$seen_bytes )
    {

      for ( a in f$info$tx_hosts )
      {
        src_host = a;
      }

      print fmt("%s: Wrong body size from host: %s. (%d versus %d)", strftime("%Y/%M/%d %H:%m:%S", f$http$ts), src_host, f$total_bytes, f$seen_bytes);
    }

  }

}

