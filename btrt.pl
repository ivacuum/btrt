#!/usr/bin/perl -T
#
# @package retracker.ivacuum.ru
# @copyright (c) 2012 vacuum
#
use strict;
no strict 'vars';

use Cache::Memcached::Fast;
use Digest::SHA1 qw(sha1_hex);
use EV;
use IO::Socket::INET qw(IPPROTO_TCP TCP_NODELAY SO_LINGER SO_REUSEADDR SOL_SOCKET);
use JSON;

do './functions.plib';

# Отключение буферизации
$| = 1;

$ev_unixtime = int(EV::now);

#
# Настройки
#
$s_ip   = '10.171.2.233';
$s_port = 2790;

$g_accept_interval   = 30;  # 30 сек
$g_accepted          = 0;
$g_announce_interval = 300; # 5 минут
$g_complete_count    = 0;   # 0 закачек
$g_debug             = 1;
$g_expire_factor     = 5;
$g_max_numwant       = 200; # 200 пиров
$g_min_numwant       = 50;  # 50 пиров
$g_rejected          = 0;   # 0 запросов
$g_starttime         = $^T;

# Особенные настройки для разрабатываемой версии
if( $0 =~ /_dev/ ) {
  use Data::Dumper;

  $g_announce_interval = 60;
  $g_expire_factor     = 2;
  $g_debug             = 2;
  $s_port++;

  &print_event('INFO', 'Запущена разрабатываемая версия');
}

%g_files;
%g_peers;

# Принудительное завершение работы (Ctrl+C)
my $sigint = EV::signal 'INT', sub {
  &retracker_shutdown('SIGINT');
};

# Принудительное завершение работы (kill <pid>)
my $sigterm = EV::signal 'TERM', sub {
  &retracker_shutdown('SIGTERM');
};

# Подключение к memcached
my $memcache = new Cache::Memcached::Fast({
  'servers' => [{
    'address' => '/var/run/memcached/memcached.lock',
    'noreply' => 1
  }]
});

# Настройки кэша
$g_cache_expire = $g_announce_interval + 60;
$g_cache_prefix = sprintf('ivacuum.ru_btrt_%d_', $s_port);

&print_event('CORE', 'Подключение к memcached установлено');

# Занесение начального состояния ретрекера в memcache
$memcache->set($g_cache_prefix . 'status', encode_json({
  'accepted'  => 0,
  'completed' => 0,
  'files'     => 0,
  'rejected'  => 0,
  'peers'     => 0,
  'uptime'    => 0
}), $g_cache_expire);

# Создание сокета
my $fh = IO::Socket::INET->new(
  Proto     => 'tcp',
  LocalAddr => $s_ip,
  LocalPort => $s_port,
  Listen    => 50000,
  ReuseAddr => SO_REUSEADDR,
  Blocking  => 0
) or die("\nНевозможно создать сокет: $!\n");
setsockopt($fh, IPPROTO_TCP, TCP_NODELAY, 1);
setsockopt($fh, SOL_SOCKET, SO_LINGER, pack('II', 1, 0));
&print_event('CORE', 'Принимаем входящие пакеты по адресу ' . $s_ip . ':' . $s_port);

# Принимаем подключения
my $event = EV::io $fh, EV::READ, sub {
  my $session = $fh->accept() or return 0; # die "accept failed: $@";

  # Клиент закрыл соединение
  return &close_connection($session) if(!$session->peerhost);

  # Неблокирующий режим работы
  $session->blocking(0);
  binmode($session);

  &print_event('RECV', 'Подключился клиент ' . $session->peerhost . ':' . $session->peerport);

  my $callback; $callback = sub {
    my $type = $_[0];

    # Таймаут
    if( $type & EV::TIMEOUT ) {
      &print_event('CORE', 'Connection timeout');
      $g_rejected++;
      return &close_connection($session);
    }

    # Ошибка
    if( $type & EV::ERROR ) {
      &print_event('CORE', 'Connection error');
      $g_rejected++;
      return &close_connection($session);
    }

    # Чтение данных
    my $s_output = '';
    sysread $session, $s_output, 1024;

    # Возможно излишняя проверка
    if( !defined $s_output ) {
      &print_event('CORE', '$s_output is not defined');
      return &close_connection($session);
    }

    $g_accepted++;

    if( $g_accepted % 100000 == 0 ) {
      &print_event('CORE', 'Подключений: ' . $g_accepted);
    }

    $ev_unixtime = int(EV::now);

    if( $s_output =~ /^GET \/ann\?(.+) HTTP/ ) {
      # Запрос к анонсеру
      my %hash = &parse_qs($1);

      $hash{'info_hash'} =~ s|\%([a-f0-9]{2})|pack('C', hex($1))|ieg;
      $hash{'peer_id'} =~ s|\%([a-f0-9]{2})|pack('C', hex($1))|ieg;

      # Поступившие данные
      my $compact = $hash{'compact'} || 1;
      my $downloaded = $hash{'downloaded'};
      my $event = $hash{'event'} || '';
      my $info_hash = $hash{'info_hash'};
      my $left = $hash{'left'};
      my $new_peer = 0;
      my $numwant = $hash{'numwant'} || 0;
      my $peer_id = $hash{'peer_id'};
      my $port = $hash{'port'} || 0;
      my $seeder = ( $left == 0 ) ? 1 : 0;
      my $uploaded = $hash{'uploaded'};
      my $user_agent;

      if( $s_output =~ /User-Agent: ([\da-zA-z\.\(\)\/]+)/ ) {
        # Торрент-клиент
        $user_agent = $1;
      } else {
        # Если клиент не передал свое название,
        # то берем сокращенное из peer_id
        $user_agent = substr($peer_id, 1, 6);
      }

      # &print_event('RECV', 'Подключился ' . $session->peerhost . ':' . $port . ' ' . $user_agent);

      # Проверка поступивших данных
      if( substr($session->peerhost, 0, 3) ne '10.' ) {
        return &btt_msg_die($session, 'Трекер доступен только для абонентов Билайн-Калуга');
      } elsif( !$info_hash or length($info_hash) != 20 ) {
        return &btt_msg_die($session, 'Неверный info_hash торрента');
      } elsif( !$peer_id or length($peer_id) != 20 ) {
        return &btt_msg_die($session, 'Неверный peer_id клиента');
      } elsif( $port <= 0 or $port > 65535 ) {
        return &btt_msg_die($session, 'Неверный порт');
      } elsif( $downloaded < 0 ) {
        return &btt_msg_die($session, 'Неверное значение downloaded');
      } elsif( $uploaded < 0 ) {
        return &btt_msg_die($session, 'Неверное значение uploaded');
      } elsif( $left < 0 ) {
        return &btt_msg_die($session, 'Неверное значение left');
      } elsif( $compact != 1 ) {
        &print_event('CORE', 'Клиент ' . $user_agent . ' не поддерживает упакованные ответы');
        return &btt_msg_die($session, 'Ваш клиент не поддерживает упакованные ответы');
      }

      # Уникальный ID пира
      # Изначально содержит 40 символов. 32 - чтобы влезло в поле кода md5
      $peer_hash = substr(sha1_hex($info_hash . $session->peerhost . $port), 0, 32);

      # &print_event('RECV', 'Клиент остановил торрент') if($event eq 'stopped');
      # &print_event('RECV', 'Клиент запустил торрент') if($event eq 'started');
      # &print_event('RECV', 'Клиент полностью скачал торрент') if($event eq 'completed');

      # Первый анонс торрента
      if( !defined $g_files{$info_hash} ) {
        $g_files{$info_hash} = {
          'complete_count' => 0,
          'leechers'       => 0,
          'mtime'          => 0,
          'peers'          => {},
          'seeders'        => 0
        };
      }

      # Первое появление пира на раздаче
      if( !defined $g_files{$info_hash}{'peers'}{$peer_hash} ) {
        if( $left > 0 or $event eq 'completed' ) {
          # Подключился новый лич
          $g_files{$info_hash}{'leechers'}++;
        } else {
          # Подключился новый сид
          $g_files{$info_hash}{'seeders'}++;
        }

        $g_files{$info_hash}{'peers'}{$peer_hash} = pack('Nn', &ip2long($session->peerhost), $port);
        $new_peer = 1;
      }

      $g_files{$info_hash}{'mtime'} = $ev_unixtime;

      # Обновление данных пира
      $g_peers{$peer_hash} = {
        'mtime'  => $ev_unixtime,
        'seeder' => $seeder
      };

      $numwant = $g_max_numwant if($numwant > $g_max_numwant);
      $numwant = $g_min_numwant if($numwant < $g_min_numwant);

      if( $event eq 'stopped' ) {
        # Удаление пира
        &delete_peer($info_hash, $peer_hash, $seeder);

        # uTorrent 2.0.4+ требует список пиров даже при остановке торрента
        # Отдаем ему самого себя
        return &btt_msg($session, {
          'complete'   => $g_files{$info_hash}{'seeders'},
          'incomplete' => $g_files{$info_hash}{'leechers'},
          'downloaded' => $g_files{$info_hash}{'complete_count'},
          'interval'   => $g_announce_interval,
          'peers'      => pack('Nn', &ip2long($session->peerhost), $port)
        });
      } elsif( $event eq 'completed' ) {
        # Клиент завершил закачку торрента - стал сидом
        $g_files{$info_hash}{'complete_count'}++;
        $g_files{$info_hash}{'leechers'}--;
        $g_files{$info_hash}{'seeders'}++;

        $g_complete_count++;
      }

      my($peers, $peers_count) = ('', 0);

      # Создание списка пиров для клиента
      foreach my $key (keys %{$g_files{$info_hash}{'peers'}}) {
        next if($key eq $peer_hash);
        next if($seeder and $g_peers{$key}{'seeder'});
        $peers .= $g_files{$info_hash}{'peers'}{$key};
        last if(++$peers_count == $numwant);
      }

      # Анонс
      return &btt_msg($session, {
        'complete'   => $g_files{$info_hash}{'seeders'},
        'incomplete' => $g_files{$info_hash}{'leechers'},
        'downloaded' => $g_files{$info_hash}{'complete_count'},
        'interval'   => $g_announce_interval,
        'peers'      => $peers
      });
    } elsif( $g_debug > 1 and $s_output =~ /^GET \/dumper HTTP/ ) {
      # Дамп данных
      use Data::Dumper;
      
      return &html_msg($session, 'Дамп данных', '<h3>g_files [' . scalar(keys(%g_files)) . ']</h3><pre>' . Dumper(%g_files) . '</pre><h3>g_peers [' . scalar(keys(%g_peers)) . ']</h3><pre>' . Dumper(%g_peers) . '</pre>');
    } elsif( $s_output =~ /^GET \/stats HTTP/ ) {
      # Запрос статистики
      return &html_msg($session, 'Статистика ретрекера', sprintf('<h3>Статистика ретрекера</h3><p>Ретрекер работает %s, обслуживает %s пиров на %s раздачах.</p><p>Подключений обслужено: %s. Отклонено по таймауту (%d сек): %.5f%% (%s).</p><p>Скачано торрентов через ретрекер: %s.</p>', &date_format($ev_unixtime - $g_starttime), &num_format(scalar(keys(%g_peers))), &num_format(scalar(keys(%g_files))), &num_format($g_accepted), $g_accept_interval, $g_rejected / ($g_accepted - $g_rejected), $g_rejected, $g_complete_count));
    } elsif( $s_output =~ /^GET \/ping HTTP/ ) {
      # Проверка отклика
      return &html_msg_simple($session, "I'm alive! Don't worry.");
    } elsif( $s_output ) {
      &print_event('CORE', 'Request: ' . $s_output);
      return &html_msg_simple($session, 'Неизвестный запрос');
    }
  };

  EV::once($session, EV::READ, $g_accept_interval, $callback);
};

##
## CRON
##
my $cron = EV::timer $g_announce_interval, $g_announce_interval, sub {
  $ev_unixtime = int(EV::now);

  #
  # Удаление информации об отключившихся пирах
  # Интервал: время анонса
  #
  foreach my $info_hash (keys %g_files) {
    foreach my $peer_hash (keys %{$g_files{$info_hash}{'peers'}}) {
      next if($ev_unixtime - $g_peers{$peer_hash}{'mtime'} <= $g_announce_interval * $g_expire_factor);

      $g_files{$info_hash}{'leechers'}-- if(!$g_peers{$peer_hash}{'seeder'});
      $g_files{$info_hash}{'seeders'}-- if($g_peers{$peer_hash}{'seeder'});
      delete $g_peers{$peer_hash};
      delete $g_files{$info_hash}{'peers'}{$peer_hash};
    }
  }

  #
  # Удаление информации об устаревших раздачах
  # Интервал: время анонса
  #
  foreach my $info_hash (keys %g_files) {
    delete $g_files{$info_hash} if($g_files{$info_hash}{'seeders'} + $g_files{$info_hash}{'leechers'} == 0);
  }

  #
  # Запись состояния ретрекера в memcache
  # Интервал: время анонса + 1 минута
  #
  $memcache->replace($g_cache_prefix . 'status', encode_json({
    'accepted'  => $g_accepted,
    'completed' => $g_complete_count,
    'files'     => scalar(keys(%g_files)),
    'rejected'  => $g_rejected,
    'peers'     => scalar(keys(%g_peers)),
    'uptime'    => $ev_unixtime - $g_starttime
  }), $g_cache_expire);
};

EV::run;