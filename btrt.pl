#!/usr/bin/perl -T
#
# @package retracker.ivacuum.ru
# @copyright (c) 2013 vacuum
#
use common::sense;
use Cache::Memcached::Fast;
use Digest::SHA1 qw(sha1_hex);
use EV;
use IO::Socket::INET qw(IPPROTO_TCP TCP_NODELAY SO_LINGER SO_REUSEADDR SOL_SOCKET);
use Ivacuum::Utils;
use Ivacuum::Utils::BitTorrent;
use JSON qw(decode_json encode_json to_json);
require './functions.pm';

# Отключение буферизации
$| = 1;

# Настройки
my $s_accepted       = 0;
my $s_complete_count = 0;
my $s_ip             = '0.0.0.0';
my $s_port           = 2790;
my $s_memcached      = '/var/run/memcached/memcached.lock';
my $s_starttime      = $^T;

my %g_cfg = (
  'announce_interval' => 300,    # 5 минут
  'cache_expire'      => 360,    # announce_interval + 1 минута
  'cache_prefix'      => 'btrt_',
  'debug'             => 1,
  'expire_factor'     => 5,
  'max_numwant'       => 200,    # 200 пиров
  'min_numwant'       => 50,     # 50 пиров
  'sitename'          => 'btrt',
);
my %g_files;
my %g_peers;

# Загрузка настроек
{
  local $/;
  open my $fh, '<', './config.json';
  my $json = <$fh>;
  my $config = decode_json($json);
  @g_cfg{keys %$config} = values %$config;
}

# Особенные настройки для разрабатываемой версии
if ($0 =~ /_dev/) {
  use Devel::Size qw(size total_size);
  
  $Devel::Size::warn = 0;

  $s_port++;
  $g_cfg{'announce_interval'} = 60;
  $g_cfg{'cache_expire'}      = 90;
  $g_cfg{'cache_prefix'}     .= 'dev_';
  $g_cfg{'expire_factor'}     = 2;
  $g_cfg{'debug'}             = 2;
}

Ivacuum::Utils::BitTorrent::set_announce_interval($g_cfg{'announce_interval'});
Ivacuum::Utils::set_debug_level($g_cfg{'debug'});
Ivacuum::Utils::set_sitename($g_cfg{'sitename'});

my $ev_unixtime = int EV::now;

# Принудительное завершение работы (INT: Ctrl+C, TERM: kill <pid>)
my $sigint = EV::signal 'INT', sub { retracker_shutdown('SIGINT'); };
my $sigterm = EV::signal 'TERM', sub { retracker_shutdown('SIGTERM'); };

# Подключение к memcached
my $memcache = new Cache::Memcached::Fast({
  'servers' => [{ 'address' => $s_memcached, 'noreply' => 1 }]
});

print_event('CORE', 'Подключение к memcached установлено');

# Занесение начального состояния ретрекера в memcache
$memcache->set($g_cfg{'cache_prefix'} . 'status', encode_json({
  'accepted'  => 0,
  'completed' => 0,
  'files'     => 0,
  'rejected'  => 0,
  'peers'     => 0,
  'uptime'    => 0,
}), $g_cfg{'cache_expire'});

# Создание сокета
my $fh = IO::Socket::INET->new(
  'Proto'     => 'tcp',
  'LocalAddr' => $s_ip,
  'LocalPort' => $s_port,
  'Listen'    => 50000,
  'ReuseAddr' => SO_REUSEADDR,
  'Blocking'  => 0,
) or die("\nНевозможно создать сокет: $!\n");
setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1;
setsockopt $fh, SOL_SOCKET, SO_LINGER, pack('II', 1, 0);
setsockopt $fh, SOL_SOCKET, 0x1000, pack('Z16 Z240', 'httpready', '') if $^O eq 'freebsd';
print_event('CORE', "Принимаем входящие пакеты по адресу $s_ip:$s_port");

# Принимаем подключения
my $event = EV::io $fh, EV::READ, sub {
  my $session = $fh->accept() or return;

  # Клиент закрыл соединение
  return close_connection($session) unless $session->peerhost;

  # Неблокирующий режим работы
  $session->blocking(0);
  binmode $session;

  print_event('RECV', 'Подключился клиент ' . $session->peerhost . ':' . $session->peerport);

  # Чтение данных
  my $s_input = '';
  sysread $session, $s_input, 1024;
  
  $s_accepted++;
  print_event('CORE', 'Подключений: ' . $s_accepted) if $s_accepted % 100000 == 0;

  $ev_unixtime = int EV::now;

  if ($s_input =~ /^GET \/ann\?(.+) HTTP/) {
    # Запрос к анонсеру
    my %hash = parse_qs($1);

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
    my $seeder = $left == 0 ? 1 : 0;
    my $uploaded = $hash{'uploaded'};
    my $user_agent;

    if ($s_input =~ /User-Agent: ([\da-zA-z\.\(\)\/]+)/) {
      # Торрент-клиент
      $user_agent = $1;
    } else {
      # Если клиент не передал свое название,
      # то берем сокращенное из peer_id
      $user_agent = substr $peer_id, 1, 6;
    }

    # print_event('RECV', 'Подключился ' . $session->peerhost . ':' . $port . ' ' . $user_agent);

    # Проверка поступивших данных
    return btt_msg_die($session, 'Трекер доступен только для абонентов Билайн-Калуга', $event) if substr($session->peerhost, 0, 3) ne '10.' and substr($session->peerhost, 0, 10) ne '192.168.1.';
    return btt_msg_die($session, 'Неверный info_hash торрента', $event) if !$info_hash or length($info_hash) != 20;
    return btt_msg_die($session, 'Неверный peer_id клиента', $event) if !$peer_id or length($peer_id) != 20;
    return btt_msg_die($session, 'Неверный порт', $event) if $port <= 0 or $port > 65535;
    return btt_msg_die($session, 'Неверное значение downloaded', $event) if $downloaded < 0;
    return btt_msg_die($session, 'Неверное значение uploaded', $event) if $uploaded < 0;
    return btt_msg_die($session, 'Неверное значение left', $event) if $left < 0;
    return btt_msg_die($session, 'Ваш клиент не поддерживает упакованные ответы', $event) if $compact != 1;

    # Уникальный ID пира
    # Изначально содержит 40 символов. 32 - чтобы влезло в поле кода md5
    my $peer_hash = substr(sha1_hex($info_hash . $session->peerhost . $port), 0, 32);

    # print_event('RECV', 'Клиент остановил торрент') if $event eq 'stopped';
    # print_event('RECV', 'Клиент запустил торрент') if $event eq 'started';
    # print_event('RECV', 'Клиент полностью скачал торрент') if $event eq 'completed';

    # Первый анонс торрента
    if (!defined $g_files{$info_hash}) {
      $g_files{$info_hash} = {
        'complete_count' => 0,
        'leechers'       => 0,
        'mtime'          => 0,
        'peers'          => {},
        'seeders'        => 0,
      };
    }

    # Первое появление пира на раздаче
    if (!defined $g_files{$info_hash}{'peers'}{$peer_hash}) {
      if ($left > 0 or $event eq 'completed') {
        # Подключился новый лич
        $g_files{$info_hash}{'leechers'}++;
      } else {
        # Подключился новый сид
        $g_files{$info_hash}{'seeders'}++;
      }

      $g_files{$info_hash}{'peers'}{$peer_hash} = pack('Nn', ip2long($session->peerhost), $port);
      $new_peer = 1;
    }

    $g_files{$info_hash}{'mtime'} = $ev_unixtime;

    # Обновление данных пира
    $g_peers{$peer_hash} = {
      'mtime'  => $ev_unixtime,
      'seeder' => $seeder,
    };

    $numwant = $g_cfg{'max_numwant'} if $numwant > $g_cfg{'max_numwant'};
    $numwant = $g_cfg{'min_numwant'} if $numwant < $g_cfg{'min_numwant'};

    if ($event eq 'stopped') {
      # Удаление пира
      delete_peer($info_hash, $peer_hash, $seeder);

      # uTorrent 2.0.4+ требует список пиров даже при остановке торрента
      # Отдаем ему самого себя
      return btt_msg($session, {
        'complete'   => $g_files{$info_hash}{'seeders'},
        'incomplete' => $g_files{$info_hash}{'leechers'},
        'downloaded' => $g_files{$info_hash}{'complete_count'},
        'interval'   => $g_cfg{'announce_interval'},
        'peers'      => pack('Nn', ip2long($session->peerhost), $port),
      });
    } elsif ($event eq 'completed') {
      # Клиент завершил закачку торрента - стал сидом
      $g_files{$info_hash}{'complete_count'}++;
      $g_files{$info_hash}{'leechers'}--;
      $g_files{$info_hash}{'seeders'}++;

      $s_complete_count++;
    }

    my($peers, $peers_count) = ('', 0);

    # Создание списка пиров для клиента
    foreach my $key (keys %{$g_files{$info_hash}{'peers'}}) {
      next if $key eq $peer_hash;
      next if $seeder and $g_peers{$key}{'seeder'};
      $peers .= $g_files{$info_hash}{'peers'}{$key};
      last if ++$peers_count == $numwant;
    }
    
    # Анонс
    return btt_msg($session, {
      'complete'   => $g_files{$info_hash}{'seeders'},
      'incomplete' => $g_files{$info_hash}{'leechers'},
      'downloaded' => $g_files{$info_hash}{'complete_count'},
      'interval'   => $g_cfg{'announce_interval'},
      'peers'      => $peers,
    });
  } elsif (($g_cfg{'debug'} > 1 or substr($session->peerhost, 0, 10) eq '192.168.1.') and $s_input =~ /^GET \/dumper HTTP/) {
    # Дамп данных
    return html_msg($session, 'Дамп данных', '<h3>g_files [' . (scalar keys %g_files) . ']</h3><pre>' . to_json(\%g_files, { pretty => 1 }) . '</pre><h3>g_peers [' . (scalar keys %g_peers) . ']</h3><pre>' . to_json(\%g_peers, { pretty => 1 }) . '</pre>');
  } elsif ($s_input =~ /^GET \/stats HTTP/) {
    # Запрос статистики
    return html_msg($session, 'Статистика ретрекера', sprintf('<h3>Статистика ретрекера</h3><p>Ретрекер работает %s, обслуживает %s пиров на %s раздачах.</p><p>Подключений обслужено: %s. Скачано торрентов через ретрекер: %s.</p>', date_format($ev_unixtime - $s_starttime), num_format(scalar keys %g_peers), num_format(scalar keys %g_files), num_format($s_accepted), $s_complete_count));
  } elsif ($s_input =~ /^GET \/ping HTTP/) {
    # Проверка отклика
    return html_msg_simple($session, "I'm alive! Don't worry.");
  } elsif ($s_input) {
    print_event('CORE', 'Request: ' . $s_input);
    return html_msg_simple($session, 'Неизвестный запрос');
  }
};

##
## CRON
##
my $cron = EV::timer $g_cfg{'announce_interval'}, $g_cfg{'announce_interval'}, sub {
  $ev_unixtime = int EV::now;

  #
  # Удаление информации об отключившихся пирах
  # Интервал: время анонса
  #
  foreach my $info_hash (keys %g_files) {
    foreach my $peer_hash (keys %{$g_files{$info_hash}{'peers'}}) {
      next if $ev_unixtime - $g_peers{$peer_hash}{'mtime'} <= $g_cfg{'announce_interval'} * $g_cfg{'expire_factor'};

      $g_files{$info_hash}{'leechers'}--
        unless $g_peers{$peer_hash}{'seeder'};
      $g_files{$info_hash}{'seeders'}--
        if $g_peers{$peer_hash}{'seeder'};
      
      delete $g_peers{$peer_hash};
      delete $g_files{$info_hash}{'peers'}{$peer_hash};
    }
  }

  #
  # Удаление информации об устаревших раздачах
  # Интервал: время анонса
  #
  foreach my $info_hash (keys %g_files) {
    delete $g_files{$info_hash}
      if $g_files{$info_hash}{'seeders'} + $g_files{$info_hash}{'leechers'} == 0;
  }

  #
  # Запись состояния ретрекера в memcache
  # Интервал: время анонса + 1 минута
  #
  $memcache->set($g_cfg{'cache_prefix'} . 'status', encode_json({
    'accepted'  => $s_accepted,
    'completed' => $s_complete_count,
    'files'     => scalar keys %g_files,
    'rejected'  => 0,
    'peers'     => scalar keys %g_peers,
    'uptime'    => $ev_unixtime - $s_starttime,
  }), $g_cfg{'cache_expire'});
};

EV::run;