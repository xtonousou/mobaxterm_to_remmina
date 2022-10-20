#! /usr/bin/env python
# Author: Sotirios Roussis <root@xtonousou.com>

import re
import os
import sys
import base64

import configparser

from getpass import getpass
from Crypto.Hash import SHA512
from Crypto.Cipher import AES, DES3


class MobaXtermCryptoSafe(object):
    """
    Ref: https://github.com/HyperSine/how-does-MobaXterm-encrypt-password
    """
    def __init__(self, master_password: bytes):
        self.key = SHA512.new(master_password).digest()[0:32]

    def decrypt(self, ciphertext: str) -> bytes:
        iv = AES.new(key=self.key, mode=AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
        cipher = AES.new(key=self.key, iv=iv, mode=AES.MODE_CFB, segment_size=8)
        return cipher.decrypt(base64.b64decode(ciphertext))


class RemminaCryptoSafe(object):
    """
    Ref: https://github.com/Rohith050/mremoteng_to_remmina
    """
    def __init__(self, secret: str):
        self.secret = base64.b64decode(secret)

    def encrypt(self, plaintext: str) -> str:
        pad = 8 - len(plaintext) % 8
        plaintext += pad * chr(0)
        return base64.b64encode(DES3.new(self.secret[:24], DES3.MODE_CBC, self.secret[24:]).encrypt(plaintext.encode())).decode()


class ConfigParserMultiOpt(configparser.RawConfigParser):
    """
    Ref: https://stackoverflow.com/questions/13921323/handling-duplicate-keys-with-configparser
    ConfigParser allowing duplicate keys. Values are stored in a list
    """

    def __init__(self):
        configparser.RawConfigParser.__init__(self, empty_lines_in_values=False, strict=False)

    def _read(self, fp, fpname):
        """Parse a sectioned configuration file.

        Each section in a configuration file contains a header, indicated by
        a name in square brackets (`[]'), plus key/value options, indicated by
        `name' and `value' delimited with a specific substring (`=' or `:' by
        default).

        Values can span multiple lines, as long as they are indented deeper
        than the first line of the value. Depending on the parser's mode, blank
        lines may be treated as parts of multiline values or ignored.

        Configuration files may include comments, prefixed by specific
        characters (`#' and `;' by default). Comments may appear on their own
        in an otherwise empty line or may be entered in lines holding values or
        section names.
        """
        elements_added = set()
        cursect = None                                                # None, or a dictionary
        sectname = None
        optname = None
        lineno = 0
        indent_level = 0
        e = None                                                            # None, or an exception
        for lineno, line in enumerate(fp, start=1):
            comment_start = None
            # strip inline comments
            for prefix in self._inline_comment_prefixes:
                index = line.find(prefix)
                if index == 0 or (index > 0 and line[index-1].isspace()):
                    comment_start = index
                    break
            # strip full line comments
            for prefix in self._comment_prefixes:
                if line.strip().startswith(prefix):
                    comment_start = 0
                    break
            value = line[:comment_start].strip()
            if not value:
                if self._empty_lines_in_values:
                    # add empty line to the value, but only if there was no
                    # comment on the line
                    if (comment_start is None and cursect is not None and optname and cursect[optname] is not None):
                        cursect[optname].append('') # newlines added at join
                else:
                    # empty line marks end of value
                    indent_level = sys.maxsize
                continue
            # continuation line?
            first_nonspace = self.NONSPACECRE.search(line)
            cur_indent_level = first_nonspace.start() if first_nonspace else 0
            if (cursect is not None and optname and cur_indent_level > indent_level):
                cursect[optname].append(value)
            # a section header or option header?
            else:
                indent_level = cur_indent_level
                # is it a section header?
                mo = self.SECTCRE.match(value)
                if mo:
                    sectname = mo.group('header')
                    if sectname in self._sections:
                        if self._strict and sectname in elements_added:
                            raise configparser.DuplicateSectionError(sectname, fpname, lineno)
                        cursect = self._sections[sectname]
                        elements_added.add(sectname)
                    elif sectname == self.default_section:
                        cursect = self._defaults
                    else:
                        cursect = self._dict()
                        self._sections[sectname] = cursect
                        self._proxies[sectname] = configparser.SectionProxy(self, sectname)
                        elements_added.add(sectname)
                    # So sections can't start with a continuation line
                    optname = None
                # no section header in the file?
                elif cursect is None:
                    raise configparser.MissingSectionHeaderError(fpname, lineno, line)
                # an option line?
                else:
                    mo = self._optcre.match(value)
                    if mo:
                        optname, vi, optval = mo.group('option', 'vi', 'value')
                        if not optname:
                            e = self._handle_error(e, fpname, lineno, line)
                        optname = self.optionxform(optname.rstrip())
                        if (self._strict and (sectname, optname) in elements_added):
                            raise configparser.DuplicateOptionError(sectname, optname, fpname, lineno)
                        elements_added.add((sectname, optname))
                        # This check is fine because the OPTCRE cannot
                        # match if it would set optval to None
                        if optval is not None:
                            optval = optval.strip()
                            # Check if this optname already exists
                            if (optname in cursect) and (cursect[optname] is not None):
                                # If it does, convert it to a tuple if it isn't already one
                                if not isinstance(cursect[optname], tuple):
                                    cursect[optname] = tuple(cursect[optname])
                                cursect[optname] = cursect[optname] + tuple([optval])
                            else:
                                cursect[optname] = [optval]
                        else:
                            # valueless option handling
                            cursect[optname] = None
                    else:
                        # a non-fatal parsing error occurred. set up the
                        # exception but keep going. the exception will be
                        # raised at the end of the file and will contain a
                        # list of all bogus lines
                        e = self._handle_error(e, fpname, lineno, line)
        # if any parsing errors occurred, raise an exception
        if e:
            raise e
        self._join_multiline_values()


class SSH(object):

    def __init__(self, *args, **kwargs):
        self.ip = kwargs.get('ip')
        self.port = kwargs.get('port')
        self.name = kwargs.get('name')
        self.username = kwargs.get('username')
        self.domain = kwargs.get('username')
        self.password = kwargs.get('password')
        self.group = kwargs.get('group')
        self.theme = kwargs.get('theme')
        self.protocol = 'SSH'
    
    def get_remmina_conf(self):
        server = self.ip
        if int(self.port) != 22:
            server = self.ip + ':' + str(self.port)

        config = configparser.ConfigParser()
        config['remmina'] = {
            'ssh_tunnel_loopback': 0,
            'window_maximize': 0,
            'protocol': self.protocol,
            'name': self.name,
            'username': self.username,
            'password': self.password,
            'ssh_proxycommand': '',
            'ssh_passphrase': '',
            'run_line': '',
            'precommand': '',
            'sshlogenabled': 0,
            'ssh_tunnel_enabled': 0,
            'ssh_charset': '',
            'window_height': '480',
            'keyboard_grab': '0',
            'window_width': '640',
            'ssh_auth': 0,
            'ignore-tls-errors': 1,
            'postcommand': '',
            'server': server,
            'disablepasswordstoring': 0,
            'ssh_color_scheme': self.theme,
            'audiblebell': 0,
            'ssh_tunnel_username': '',
            'sshsavesession': 0,
            'ssh_hostkeytypes': '',
            'ssh_tunnel_password': '',
            'profile-lock': 0,
            'sshlogfolder': '',
            'group': self.group,
            'ssh_tunnel_server': '',
            'ssh_ciphers': '',
            'enable-autostart': 0,
            'ssh_kex_algorithms': '',
            'ssh_compression': 0,
            'ssh_tunnel_auth': 0,
            'ssh_tunnel_certfile': '',
            'notes_text': '',
            'exec': '',
            'viewmode': 1,
            'sshlogname': '',
            'ssh_tunnel_passphrase': '',
            'ssh_tunnel_privatekey': '',
            'ssh_stricthostkeycheck': 0,
            'ssh_forward_x11': 0,
        }

        return config

    def __str__(self):
        return 'ssh'


class RDP(object):

    def __init__(self, *args, **kwargs):
        self.protocol = 'RDP'
        self.ip = kwargs.get('ip')
        self.port = kwargs.get('port')
        self.name = kwargs.get('name')
        self.username = kwargs.get('username')
        self.domain = kwargs.get('username')
        self.password = kwargs.get('password')
        self.group = kwargs.get('group')

        # handle domain\username style
        if '\\' in self.username:
            parts = self.username.split('\\')
            self.domain = parts[0]
            self.username = parts[1]
        
        # handle username@domain style
        if '@' in self.username:
            parts = self.username.split('@')
            self.username = parts[0]
            self.domain = parts[1]
        
        # handle dot notation for MACHINE domain
        if self.domain == '.':
            self.domain = ''
    
    def get_remmina_conf(self):
        server = self.ip
        if int(self.port) != 3389:
            server = self.ip + ':' + str(self.port)

        config = configparser.ConfigParser()
        config['remmina'] = {
            'password': self.password,
            'gateway_username': '',
            'notes_text': '',
            'vc': '',
            'preferipv6': 0,
            'ssh_tunnel_loopback': 0,
            'serialname': '',
            'tls-seclevel': '',
            'freerdp_log_level': 'INFO',
            'printer_overrides': '',
            'name': self.name,
            'console': 0,
            'colordepth': 99,
            'security': '',
            'precommand': '',
            'disable_fastpath': 0,
            'left-handed': 0,
            'postcommand': '',
            'multitransport': 0,
            'group': self.group,
            'server': server,
            'ssh_tunnel_certfile': '',
            'glyph-cache': 0,
            'ssh_tunnel_enabled': 0,
            'disableclipboard': 0,
            'parallelpath': '',
            'audio-output': '',
            'monitorids': '',
            'cert_ignore': 0,
            'serialpermissive': 0,
            'gateway_server': '',
            'protocol': self.protocol,
            'ssh_tunnel_password': '',
            'old-license': 0,
            'resolution_mode': 2,
            'pth': '',
            'loadbalanceinfo': '',
            'disableautoreconnect': 0,
            'clientbuild': '',
            'clientname': '',
            'resolution_width': 0,
            'drive': '',
            'relax-order-checks': 0,
            'username': self.username,
            'base-cred-for-gw': 0,
            'gateway_domain': '',
            'profile-lock': 0,
            'rdp2tcp': '',
            'gateway_password': '',
            'rdp_reconnect_attempts': '',
            'domain': self.domain,
            'serialdriver': '',
            'restricted-admin': 0,
            'smartcardname': '',
            'multimon': 0,
            'serialpath': '',
            'network': 'none',
            'exec': '',
            'enable-autostart': 0,
            'usb': '',
            'shareprinter': 0,
            'ssh_tunnel_passphrase': '',
            'disablepasswordstoring': 0,
            'shareparallel': 0,
            'quality': 9,
            'span': 0,
            'parallelname': '',
            'ssh_tunnel_auth': 0,
            'keymap': '',
            'ssh_tunnel_username': '',
            'execpath': '',
            'shareserial': 0,
            'resolution_height': 0,
            'timeout': '',
            'useproxyenv': 0,
            'sharesmartcard': 0,
            'freerdp_log_filters': '',
            'microphone': '',
            'dvc': '',
            'ssh_tunnel_privatekey': '',
            'gwtransp': 'http',
            'ssh_tunnel_server': '',
            'ignore-tls-errors': 1,
            'disable-smooth-scrolling': 0,
            'gateway_usage': 0,
            'sound': 'off',
            'websockets': 0,
        }

        return config

    def __str__(self):
        return 'rdp'


class Converter(object):

    def __init__(self):
        self.config = ConfigParserMultiOpt()
        self.config.read(sys.argv[1])

        self.theme_dir = '/usr/share/remmina/theme'
        self.theme_def = 'Linux'
        self.theme = self.theme_def
        self.theme_map = {t.replace('.colors', '').lower(): i for i, t in enumerate(['Linux', 'Tango', 'Gruvbox', 'Solarized Dark', 'Solarized Light', 'XTerm', 'Custom', ] + sorted(os.listdir(self.theme_dir)))}

        self.with_password = False
        self.mobaxterm_safe, self.remmina_safe = None, None

        if len(sys.argv) > 2:
            self.with_password = True if sys.argv[2].lower() in ('--decrypt', '--with-passwords', '--passwords', ) else False
            if self.with_password is True:
                mobaxterm_master_password = getpass('Enter MobaXterm master password: ')
                self.mobaxterm_safe = MobaXtermCryptoSafe(mobaxterm_master_password.encode('cp1251'))
                remmina_secret = getpass('Enter Remmina secret: ')
                self.remmina_safe = RemminaCryptoSafe(remmina_secret)

        if sys.argv[-2] in ('--color-theme', '--theme', '--color-scheme', '--colors', ):
            self.theme = sys.argv[-1]
            if self.theme.lower() not in self.theme_map.keys():
                print('Warning', self.theme, 'cannot be found. Using a default one instead')
                self.theme = self.theme_def

        self.export_dir = './exported'
        self.export_file = '{group}_{protocol}_{name}_{ip}.remmina'
        self.moba_proto_map = {
            0: SSH,
            4: RDP,
        }

        self.prepare_fs()

    @staticmethod
    def get_valid_filename(name):
        s = str(name).strip().replace(' ', '_')
        s = re.sub(r'(?u)[^-\w.]', '', s)
        return s

    def prepare_fs(self):
        if not os.path.isdir(self.export_dir):
            os.mkdir(self.export_dir)
    
    def to_remmina(self):
        # Passwords
        passwords = {}
        if self.with_password is True:
            tmp_passwords = dict(self.config.items('Passwords'))
            for k, v in tmp_passwords.items():
                if isinstance(v, (tuple, list, )):
                    for credential in v:
                        credential = credential.split('=')
                        part_k = credential[0]
                        part_v = '='.join(credential[1:])

                        if part_k not in passwords:
                            passwords[part_k] = part_v
                    continue
                elif '@' not in k:
                    credential = v.split('=')
                    part_k = credential[0]
                    part_v = '='.join(credential[1:])

                    if part_k not in passwords:
                        passwords[part_k] = part_v

                    continue
            
                if k not in passwords:
                    passwords[k] = v
            del tmp_passwords

        # Sessions
        for section in self.config.sections():
            # filter only sessions
            if section.lower().startswith('bookmarks'):
                bookmark = dict(self.config.items(section))

                # skip folders without sessions
                if len(bookmark.keys()) == 2:
                    continue

                # construct group name for remmina
                path = bookmark.get('subrep', '').replace('\\', '/')

                # construct session files
                for session_name, session_info in bookmark.items():
                    if session_name in ('subrep', 'imgnum', ):
                        continue

                    # get the session required info parts
                    parts = session_info.split('#')[2].split('%')

                    class_ref = self.moba_proto_map.get(int(parts[0]))
                    # unsupported protocols by Remmina, are skipped
                    if not class_ref:
                        continue

                    ip = parts[1]
                    username = parts[3]
                    password = '.'
                    if self.with_password is True:
                        ciphertext = passwords.get('{username}@{ip}'.format(username=username, ip=ip))
                        if ciphertext is not None:
                            plain_text = self.mobaxterm_safe.decrypt(ciphertext).decode('ansi')
                            password = self.remmina_safe.encrypt(plain_text)

                    session = class_ref(ip=ip,
                                        name=session_name,
                                        port=parts[2],
                                        username=username,
                                        group=path,
                                        password=password,
                                        theme=self.theme)

                    filename = self.export_file.format(group=path.lower().replace('/', '-'),
                                                       protocol=str(session),
                                                       name=session_name.lower().replace(' ', '-').replace('.', '-'),
                                                       ip=parts[1].replace('.', '-'))
                    filename = self.get_valid_filename(filename)
                    if not filename:
                        print('Cannot export {name} as its filename may act suspiciously on the target filesystem'.format(name=session_name))
                        continue

                    with open(self.export_dir + '/' + filename, 'w') as f:
                        session.get_remmina_conf().write(f)

        print('Successfully converted and exported Remmina sessions to "{edir}". Copy them to "~/.local/share/remmina" directory in order to be loaded by Remmina.'.format(edir=self.export_dir))


if __name__ == '__main__':
    Converter().to_remmina()
