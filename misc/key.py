#!/usr/bin/env python3

import argparse
import base64
import hashlib
import yaml
import json
import os
from abc import abstractmethod
from enum import Enum
from typing import Optional

import ecdsa
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from jinja2 import Environment, FileSystemLoader, select_autoescape

import utils

verbose = 1
hash_algorithm = hashlib.sha256
signature_algorithm = ecdsa.curves.SECP256k1
max_trust_slots = 4
signature_size = 64
digest_size = hash_algorithm().digest_size
PAGE_SIZE = 4096


def round_down(num, divisor):
    return num - (num % divisor)


def round_up(num, divisor):
    return num + (divisor - num % divisor)


def get_segment_info(p: Segment, *idents):
    v = (p.header[e] for e in idents)
    return v


def get_segment_file_offset(n):
    return get_segment_info(n, 'p_offset')


def get_segment_file_size(n):
    return get_segment_info(n, 'p_filesz')


def get_segment_vaddr(n):
    return get_segment_info(n, 'p_vaddr')


def get_segment_vaddr_size(n):
    return get_segment_info(n, 'p_memsz')


class ELF:
    def __init__(self, path):
        self.path = path
        self.elf: ELFFile = None

    def load(self):
        f = open(self.path, 'rb')
        self.elf = ELFFile(f)
        return self

    def find_section(self, name: str):
        for s in self.elf.iter_sections():
            if s.name == name:
                return s
        return None

    def find_bss(self):
        for s in self.elf.iter_sections():
            if s.name == '.bss':
                return s.header['sh_addr'], s.header['sh_size']

    def load_page(self, fa, va, length):
        page = bytearray(PAGE_SIZE)
        self.elf.stream.seek(fa)
        ld = self.elf.stream.read(length)
        assert len(ld) == length
        va_off = va % PAGE_SIZE
        page[va_off: va_off + length] = ld
        return page

    def dump_page(self, page, va):
        print(f'-- {PAGE_SIZE} B --')
        for g16 in range(0, PAGE_SIZE // 16):
            s16 = g16 * 16
            addr_line = f'{va + s16:08x}: '
            g16_list = []
            for g8 in range(0, 2):
                s8 = s16 + g8 * 8
                g8_list = []
                for g4 in range(0, 2):
                    s4 = s8 + g4 * 4
                    g4_line = ' '.join(f'{b:02x}' for b in page[s4:s4 + 4])
                    g8_list.append(g4_line)
                g8_line = '  '.join(g8_list)
                g16_list.append(g8_line)
            g16_line = '    '.join(g16_list)
            print(addr_line + g16_line)
        print('------')

    def sha256sum(self):
        m = hashlib.sha256()
        bss_va, bss_sz = self.find_bss()
        for p in self.elf.iter_segments():
            if p.header['p_type'] == 'PT_LOAD':
                # simulate elf loading
                fa, va, fz, vz = get_segment_info(
                    p, 'p_offset', 'p_vaddr', 'p_filesz', 'p_memsz')
                zva = va + fz
                eva = round_up(va + vz, PAGE_SIZE)
                length = 0
                increment = 0
                while va < zva:
                    va += increment
                    fa += increment
                    if va >= eva:
                        break
                    if bss_va <= va and va + PAGE_SIZE <= bss_va + bss_sz:
                        increment = PAGE_SIZE
                        continue
                    if va % PAGE_SIZE != 0:
                        length = min(PAGE_SIZE - va % PAGE_SIZE,
                                     zva - va)
                        page = self.load_page(fa, va, length)
                        # update the incremental length to be page aligned
                        increment = PAGE_SIZE - va % PAGE_SIZE
                    elif va < round_down(zva, PAGE_SIZE):
                        length = PAGE_SIZE
                        page = self.load_page(fa, va, length)
                        increment = PAGE_SIZE
                    elif va < zva and fz > 0:
                        length = zva - va
                        page = self.load_page(fa, va, length)
                        increment = PAGE_SIZE
                    else:
                        increment = PAGE_SIZE
                        page = bytearray(PAGE_SIZE)
                    global verbose
                    if verbose >= 2:
                        print(
                            f'{va:08x} {length:08x}: {hash_algorithm(page).hexdigest()}')
                    if verbose >= 3:
                        self.dump_page(page, round_down(va, PAGE_SIZE))
                    m.update(page)
        return m

    @staticmethod
    def add_section(objcopy, sec_name, sec_file, sec_flags, in_file, out_file):
        utils.Run.run(f'{objcopy} --add-section {sec_name}={sec_file} ' +
                      f'--set-section-flags {sec_name}={sec_flags} {in_file} {out_file}')

    @staticmethod
    def update_section(objcopy, sec_name, sec_file, in_file, out_file):
        utils.Run.run(f'{objcopy} --update-section {sec_name}={sec_file} {in_file} {out_file}')

    def close(self):
        self.elf.stream.close()


def load_pem(pem_path, pk=False):
    with open(pem_path, 'r+') as f:
        pem = f.read()
        if pem is not None:
            try:
                if pk is True:
                    k = ecdsa.VerifyingKey.from_pem(pem)
                else:
                    k = ecdsa.SigningKey.from_pem(pem)
                assert k.curve == signature_algorithm
                return k, pem
            except OSError as e:
                utils.Msg.panic(
                    f'Error when read {pem_path}: {e}. corrupted file!')
        else:
            utils.Msg.panic(
                f'Error when read {pem_path}: no content. corrupted file!')


def load_cert(cert_path):
    with open(cert_path) as f:
        try:
            cert = json.loads(f.read())
            if GenericCommand.ID_PUBLIC_KEY not in cert or \
                    GenericCommand.ID_SIGNATURE not in cert:
                utils.Msg.panic(
                    f'Error when read {cert_path}: not a valid certificate!')
            else:
                pk = ecdsa.VerifyingKey.from_pem(
                    cert[GenericCommand.ID_PUBLIC_KEY])
                sig = base64.b64decode(cert[GenericCommand.ID_SIGNATURE])
                return pk, sig
        except OSError as e:
            utils.Msg.panic(
                f'Error when read {cert_path}: {e}. corrupted file!')


def load_pem_auto(pem_path):
    pk = False
    with open(pem_path, 'r+') as f:
        pem = f.read()
        if pem.startswith('-----BEGIN PUBLIC KEY-----'):
            pk = True
        else:
            pk = False
    return load_pem(pem_path, pk)


class GenericCommand:
    ID_PUBLIC_KEY = "public_key"
    ID_SIGNATURE = "signature"

    def __init__(self, args: argparse.Namespace):
        self.args = args

    @abstractmethod
    def execute(self):
        pass


class CommandNew(GenericCommand):
    def execute(self):
        sk = ecdsa.SigningKey.generate(
            curve=signature_algorithm, hashfunc=hash_algorithm)
        pem = sk.to_pem().decode('ascii')
        with open(self.args.out_file, 'w+') as f:
            f.write(pem)


class CommandEmbed(GenericCommand):
    def execute(self):
        sk, pem = load_pem(self.args.keypair)
        # write to c file
        misc = os.path.dirname(os.path.abspath(__file__))
        tmpl = os.path.join(misc, 'template')
        env = Environment(
            loader=FileSystemLoader(tmpl),
            autoescape=select_autoescape(['c']),
            trim_blocks=True
        )
        key = env.get_template('key.c')
        key.stream(
            input=self.args.keypair,
            pem=pem.split('\n'),
            var=self.args.var
        ).dump(self.args.out_file)


class CommandExtract(GenericCommand):
    def execute(self):
        sk, pem = load_pem(self.args.keypair)
        pk = sk.get_verifying_key()
        with open(self.args.out_file, 'w+') as f:
            f.write(pk.to_pem().decode('ascii'))


class CommandAuthorize(GenericCommand):
    def execute(self):
        sk, _ = load_pem(self.args.keypair)
        pk, pk_pem = load_pem(self.args.pubkey, pk=True)
        pk_bin = pk.to_string('uncompressed')
        sig: bytes = sk.sign(pk_bin, hashfunc=hashlib.sha256)
        sig_b64 = base64.b64encode(sig).decode('ascii')
        cert = {GenericCommand.ID_PUBLIC_KEY: pk_pem,
                GenericCommand.ID_SIGNATURE: sig_b64}

        with open(self.args.out_file, 'w+') as f:
            f.write(json.dumps(cert))


class CommandValidate(GenericCommand):
    def execute(self):
        sk, _ = load_pem(self.args.keypair)
        pk, sig = load_cert(self.args.cert)
        vk: ecdsa.VerifyingKey = sk.get_verifying_key()
        pk_bin = pk.to_string('uncompressed')
        v = vk.verify(sig, pk_bin, hashfunc=hashlib.sha256,
                      sigdecode=ecdsa.util.sigdecode_der)
        if v:
            print('valid signature.')
        else:
            print('invalid signature')
            exit(1)


def create_empty_file(path: str, size: int):
    with open(path, 'wb+') as f:
        f.seek(size - 1)
        f.write(b'\0')


class CommandElfSkeleton(GenericCommand):
    def __init__(self, args):
        super().__init__(args)
        self.prepared = f'{self.args.elf}.prepared'

    def prepare_elf_structure(self, elf_in: str, elf_out: str, pk_size: int):
        objcopy = f'{self.args.binutils}objcopy'
        f_pk = f'{self.args.elf}.pk.pem'
        f_sig_pk = f'{self.args.elf}.sig_pk.sig'
        f_sig_bin = f'{self.args.elf}.sig_bin.sig'
        f_trust = f'{self.args.elf}.trust'
        f_trust_sig = f'{self.args.elf}.trust.sig'
        # create empty files
        create_empty_file(f_pk, pk_size)
        create_empty_file(f_sig_pk, signature_size)
        create_empty_file(f_sig_bin, signature_size)
        create_empty_file(f_trust, max_trust_slots * digest_size)
        create_empty_file(f_trust_sig, signature_size)
        # add sections
        flg = 'noload,readonly'
        ELF.add_section(objcopy, '.enclave.public_key', f_pk, flg, elf_in, elf_out)
        ELF.add_section(objcopy, '.enclave.pubkey_sig', f_sig_pk, flg, elf_out, elf_out)
        ELF.add_section(objcopy, '.enclave.binary_sig', f_sig_bin, flg, elf_out, elf_out)
        ELF.add_section(objcopy, '.enclave.trust', f_trust, flg, elf_out, elf_out)
        ELF.add_section(objcopy, '.enclave.trust_sig', f_trust_sig, flg, elf_out, elf_out)

    def execute(self):
        sk, _ = load_pem(self.args.keypair)
        pk, sig_pk = load_cert(self.args.cert)
        # update elf file header
        pk_bin = pk.to_pem().decode('ascii') + '\0'
        self.prepare_elf_structure(self.args.elf, self.prepared, len(pk_bin))


class CommandSign(CommandElfSkeleton):
    def generate_sign_fragments(
            self, pk: ecdsa.VerifyingKey, sig_pk: bytes, sig_bin: bytes):
        f_pk = f'{self.args.elf}.pk.pem'
        f_sig_pk = f'{self.args.elf}.sig_pk.sig'
        f_sig_bin = f'{self.args.elf}.sig_bin.sig'
        with open(f_pk, 'w+') as f:
            f.write(pk.to_pem().decode('ascii'))
            f.write('\0')
        with open(f_sig_pk, 'wb+') as f:
            f.write(sig_pk)
        with open(f_sig_bin, 'wb+') as f:
            f.write(sig_bin)
        return f_pk, f_sig_pk, f_sig_bin

    def update_elf_sections(self, elf_in, elf_out, f_pk, f_sig_pk, f_sig_bin):
        objcopy = f'{self.args.binutils}objcopy'
        ELF.update_section(objcopy, '.enclave.public_key', f_pk, elf_in, elf_out)
        ELF.update_section(objcopy, '.enclave.pubkey_sig', f_sig_pk, elf_out, elf_out)
        ELF.update_section(objcopy, '.enclave.binary_sig', f_sig_bin, elf_out, elf_out)

    def execute(self):
        elf = ELF(self.args.elf).load()
        if elf.find_section('.enclave.public_key') is None:
            super().execute()
        else:
            self.prepared = self.args.elf

        sk, _ = load_pem(self.args.keypair)
        pk, sig_pk = load_cert(self.args.cert)
        # measure elf
        elf = ELF(self.prepared).load()
        h = elf.sha256sum().digest()
        sig_bin = sk.sign(h, hashfunc=hashlib.sha256)
        global verbose
        if verbose >= 1:
            print(f'binary hash ({len(h)}B): \n {h.hex()} \n')
            print(f'verifying key ({len(pk.to_pem())}B): \n {pk.to_pem().decode("ascii")} \n')
            print(f'binary signature ({len(sig_bin)}B): \n {sig_bin.hex()} \n')
            print(f'pubkey signature ({len(sig_pk)}B): \n {sig_pk.hex()} \n')
        # attach the signatures
        self.update_elf_sections(
            self.prepared, self.args.out_file,
            *self.generate_sign_fragments(pk, sig_pk, sig_bin))


class CommandHash(GenericCommand):
    def execute(self):
        elf = ELF(self.args.elf).load()
        h = elf.sha256sum().digest()
        with open(self.args.out_file, 'w+') as f:
            f.write(h.hex())


class CommandFingerprint(GenericCommand):
    def execute(self):
        k, _ = load_pem_auto(self.args.keypair)
        if k is ecdsa.keys.SigningKey:
            pk = k.verifying_key
        else:
            pk = k
        b = pk.to_string()
        h = hashlib.md5(b).digest()
        print(':'.join(f'{x:02x}' for x in h))


class CommandTrust(CommandElfSkeleton):
    def load_trust_config(self, f_trust):
        with open(f_trust, 'r') as f:
            return yaml.safe_load(f)

    def generate_trust_fragments(self, trust: list, sk):
        slots = bytearray(max_trust_slots * digest_size)
        for i, t in enumerate(trust):
            slots[i * 32: (i + 1) * 32] = bytes.fromhex(t)
        sig = sk.sign(slots, hashfunc=hashlib.sha256)
        if verbose >= 1:
            print(f'trust signature ({len(sig)}B): \n {sig.hex()} \n')
        f_trust = f'{self.args.elf}.trust'
        f_trust_sig = f'{self.args.elf}.trust_sig'
        with open(f_trust, 'wb+') as f:
            f.write(slots)
        with open(f_trust_sig, 'wb+') as f:
            f.write(sig)
        return f_trust, f_trust_sig

    def update_elf_sections(self, elf_in, elf_out, f_trust, f_trust_sig):
        objcopy = f'{self.args.binutils}objcopy'
        ELF.update_section(objcopy, '.enclave.trust', f_trust, elf_in, elf_out)
        ELF.update_section(objcopy, '.enclave.trust_sig', f_trust_sig, elf_out, elf_out)

    def execute(self):
        elf = ELF(self.args.elf).load()
        if elf.find_section('.enclave.trust') is None:
            super().execute()
        else:
            self.prepared = self.args.elf
        sk, _ = load_pem(self.args.keypair)
        # load trust config
        trust = self.load_trust_config(self.args.trust)['trust-remote']
        global verbose
        if verbose >= 1:
            for i, t in enumerate(trust):
                print(f'trust [{i}] = {t}')
        # generate trust fragments
        f_trust, f_trust_sig = self.generate_trust_fragments(trust, sk)
        # attach the signatures
        self.update_elf_sections(
            self.prepared, self.args.out_file,
            f_trust, f_trust_sig)


class KeyCommand(Enum):
    new = ("new --out <keypair_pem>",
           "generate new signing keys",
           CommandNew)
    embed = ("embed --out <c_file> --keypair <pem> --var <variable name>",
             "generate c files holding the keypair",
             CommandEmbed)
    extract = ("extract --out <pubkey_pem> --keypair <pem>",
               "extract public (verifying) key for keypair <pem>",
               CommandExtract)
    authorize = ("authorize --out <cert> --keypair <pem> --pubkey <pem>",
                 "create a certificate for <pubkey> that is signed by <keypair>",
                 CommandAuthorize)
    validate = ("validate --keypair <pem> --cert <cert>",
                "validate if the given certificate is valid",
                CommandValidate)
    sign = (
        "sign --out <out_elf> --keypair <pem> --cert <cert> --elf <in_elf> --binutils <prefix_of_binutils>",
        "sign and attach the signatures of the measurement to the elf binary",
        CommandSign)
    trust = (
        "trust --out <out_elf> --keypair <pem> --cert <cert> --config <trust_config> --elf <in_elf> --binutils <prefix_of_binutils>",
        "sign and attach the remote trusted entities to the elf binary",
        CommandTrust)
    hash = ("hash --out <hash> --elf <in_elf>",
            "measure the elf and save the hash",
            CommandHash)
    fingerprint = ("fingerprint --keypair <pem>",
                   "calculate the fingerprint of the input key",
                   CommandFingerprint)

    def usage(self):
        return self.value[0]

    def help(self):
        return self.value[1]

    def command(self):
        return self.value[2]


class Main:
    @staticmethod
    def main():
        # argument check
        parser = argparse.ArgumentParser(description='key management utilities',
                                         formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-c', '--command', dest='cmd',
                            choices=[c.name for c in KeyCommand],
                            required=True,
                            help='command to be executed:\n' +
                                 '\n'.join([f'{c.usage()}\n\t{c.help()}\n'
                                            for c in KeyCommand]))
        parser.add_argument('-o', '--out', dest='out_file', type=utils.new_file,
                            action='store', required=False,
                            help='output file path')
        parser.add_argument('-k', '--keypair', dest='keypair',
                            type=utils.file_path,
                            action='store', required=False,
                            help='input keypair')
        parser.add_argument('-p', '--pubkey', dest='pubkey',
                            type=utils.file_path,
                            action='store', required=False,
                            help='input public key')
        parser.add_argument('-r', '--cert', dest='cert', type=utils.file_path,
                            action='store', required=False,
                            help='input certificate')
        parser.add_argument('-t', '--trust', dest='trust', type=utils.file_path,
                            action='store', required=False,
                            help='input trust config [yaml]')
        parser.add_argument('-e', '--elf', dest='elf', type=utils.file_path,
                            action='store', required=False,
                            help='input elf binary')
        parser.add_argument('-b', '--binutils', dest='binutils', type=str,
                            action='store', required=False,
                            help='prefix of binutils for operating on the elf')
        parser.add_argument('-n', '--var', dest='var', type=utils.c_identifier,
                            action='store', required=False,
                            help='input elf binary')
        args, leftover = parser.parse_known_args()

        # check arguments
        cmd = args.cmd
        if cmd == KeyCommand.new.name:
            utils.check_args(args, 'out_file')
        elif cmd == KeyCommand.embed.name:
            utils.check_args(args, 'out_file', 'keypair', 'var')
        elif cmd == KeyCommand.extract.name:
            utils.check_args(args, 'out_file', 'keypair')
        elif cmd == KeyCommand.authorize.name:
            utils.check_args(args, 'out_file', 'keypair', 'pubkey')
        elif cmd == KeyCommand.sign.name:
            utils.check_args(args, 'out_file', 'keypair', 'cert', 'elf',
                             'binutils')
        elif cmd == KeyCommand.hash.name:
            utils.check_args(args, 'out_file', 'elf')
        elif cmd == KeyCommand.validate.name:
            utils.check_args(args, 'keypair', 'cert')
        elif cmd == KeyCommand.trust.name:
            utils.check_args(args, 'out_file', 'keypair', 'cert', 'trust', 'elf',
                             'binutils')

        # run command
        c = KeyCommand[cmd].command()(args)
        c.execute()


if __name__ == "__main__":
    Main.main()
