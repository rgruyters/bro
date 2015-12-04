function filter_body ( rec: Files::Info ) : bool
{
  return rec$total_bytes != rec$seen_bytes;
}

event bro_init()
{
  Log::add_filter(Files::LOG, [
    $name = "size-mismatch",
    $path = "size-mismatch",
    $pred = filter_body
  ]);
}

