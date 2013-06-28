#
# Удаление пира
#
sub delete_peer {
  my($info_hash, $peer_hash, $seeder) = @_;

  if (defined $g_files{$info_hash}{'peers'}{$peer_hash}) {
    delete $g_files{$info_hash}{'peers'}{$peer_hash};

    $g_files{$info_hash}{'seeders'}-- if $seeder;
    $g_files{$info_hash}{'leechers'}-- unless $seeder;
  }

  delete $g_peers{$peer_hash} if defined $g_peers{$peer_hash};
}

#
# Завершение работы ретрекера
#
sub retracker_shutdown {
  my($signal) = @_;

  print "\n";
  print_event('CORE', "Получен сигнал: $signal");
  print_event('CORE', 'Завершение работы ретрекера...');
  EV::break;
  exit 0;
}

1;