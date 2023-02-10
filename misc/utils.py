#
# Utilities for other python modules
#
import sys


class Msg:
	class Color:
		HEADER = '\033[95m'
		OKBLUE = '\033[94m'
		OKGREEN = '\033[92m'
		WARNING = '\033[93m'
		FAIL = '\033[91m'
		ENDC = '\033[0m'
		BOLD = '\033[1m'
		UNDERLINE = '\033[4m'
		ALERT = '\033[91;5m'

	class BuildError(Exception):
		'''Build error because command execution failed.'''
		pass

	@staticmethod
	def header(s, end='\n'):
		print(Msg.Color.HEADER + s + Msg.Color.ENDC, end=end)

	@staticmethod
	def info(s, end='\n'):
		print(Msg.Color.OKBLUE + s + Msg.Color.ENDC, end=end)

	@staticmethod
	def ok(s, end='\n'):
		print(Msg.Color.OKGREEN + s + Msg.Color.ENDC, end=end)

	@staticmethod
	def warn(s, end='\n'):
		print(Msg.Color.WARNING + s + Msg.Color.ENDC, end=end)

	@staticmethod
	def alert(s):
		return Msg.Color.FAIL + s + Msg.Color.ENDC

	@staticmethod
	def error(s, end='\n'):
		sys.stderr.write(Msg.Color.FAIL + s + end + Msg.Color.ENDC)
		exit(1)

	@staticmethod
	def panic(s, end='\n'):
		sys.stderr.write(Msg.Color.BOLD + Msg.Color.FAIL + s + end + Msg.Color.ENDC)
		raise (Msg.BuildError(s))

	@staticmethod
	def critic(s, end='\n'):
		sys.stderr.write(Msg.Color.UNDERLINE + Msg.Color.FAIL + s + Msg.Color.ENDC,
			  end=end)


import distutils.spawn, os, subprocess, shlex
import re
import pwd
import getpass
import time
import shutil


class Run:
	@staticmethod
	def run(cmd):
		if os.system(cmd) != 0:
			Msg.panic('{0} executed with error.'.format(cmd))

	@staticmethod
	def sudo(cmd):
		if os.system('sudo ' + cmd) != 0:
			Msg.panic('{0} executed with error.'.format(cmd))

	@staticmethod
	def run_return_code(cmd):
		return os.system(cmd)

	@staticmethod
	def run_force(cmd):
		s = os.system(cmd)
		return s

	@staticmethod
	def exec(cmd):
		proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
		(out, err) = proc.communicate()
		output = ''
		if out:
			output = output + out.decode('utf-8')
		if err:
			output = output + err.decode('utf-8')
		return output

	@staticmethod
	def shell(cmd):
		proc = subprocess.Popen(shlex.split(
			cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
		return proc

	@staticmethod
	def grep(s, pattern):
		return '\n'.join(re.findall(r'^.*%s.*?$' % pattern, s, flags=re.M))

	@staticmethod
	def owner_of(file):
		return pwd.getpwuid(os.stat(file).st_uid).pw_name

	@staticmethod
	def size_of(file):
		return os.path.getsize(file)

	@staticmethod
	def can_read(file):
		return os.access(file, os.R_OK)

	@staticmethod
	def check_read(file):
		if not Run.can_read(file):
			Msg.error('cannot read {0}'.format(file))

	@staticmethod
	def check_read_files(files):
		failed = []
		for f in files:
			if not Run.can_read(f):
				Msg.warn('cannot read {0}'.format(f))
				failed.append(f)
		if failed:
			Msg.info('sudo chmod o+r {0}'.format(' '.join(failed)))
			Msg.error('please make sure you have permission to read the above files before proceed!')

	@staticmethod
	def check_exec(cmd, help_info=''):
		if distutils.spawn.find_executable(cmd) is None:
			Msg.error(
				'cannot find {0} in the system, please install it and then execute. {1}'.format(
					cmd, help_info))

	@staticmethod
	def check_file(path, help_info=''):
		if not os.path.isfile(path):
			Msg.error('cannot find {}. {}'.format(path, help_info))

	@staticmethod
	def check_ownership(path, owner=getpass.getuser(), help_info=''):
		if os.path.exists(path) and Run.owner_of(path) != owner:
			Msg.error(('No permission to read {0}. Set the owner of {0} to be {1} by:\n' +
						'  sudo chown {1} {0}\n {2}').format(path, owner, help_info))

	@staticmethod
	def fsync():
		Run.run('sync --file-system')

	@staticmethod
	def sleep(secs=1):
		time.sleep(secs)

	@staticmethod
	def configure(match, new, file):
		Run.run(f'grep \'^{match}\' {file} && sed -i -E \'s/^{match}.*/{new}/g\' {file} || echo \'{new}\' >> {file}')

	@staticmethod
	def cp(from_file, to_file):
		Msg.info(f'{from_file} -> {to_file}')
		shutil.copy2(from_file, to_file)

	@staticmethod
	def rm(file):
		shutil.rmtree(file, ignore_errors=True)

import queue
import threading

class InteractiveShell:
	def __init__(self, cmd):
		self.buffer = ''
		self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
										stderr=subprocess.PIPE, shell=False, universal_newlines=True)
		self.stdout = self.proc.stdout
		self.stderr = self.proc.stderr
		self.output_queue = queue.Queue()
		self.output_thread = threading.Thread(target = self.output_daemon)
		self.output_thread.daemon = True
		self.output_thread.start()

	def output_daemon(self):
		for line in iter(self.stdout.read, b''):
			self.output_queue.put(line)
		for line in iter(self.stderr.read, b''):
			self.output_queue.put(line)
		self.stdout.close()

	def read(self):
		output = ''
		try:
			while True:
				output += self.output_queue.get_nowait()
		except queue.Empty:
			self.buffer += output
			return output

	def send(self, s=''):
		self.proc.stdin.write(s)
		self.proc.stdin.flush()
		self.buffer += s

	def sendline(self, s=''):
		self.send(s + os.linesep)

	def expect(self, map={}):
		output = read()
		for (pattern, result) in map.items():
			if re.search(pattern, output, re.MULTILINE):
				return result
		return None

	def exec(self, command='', map={}):
		self.sendline(command)
		result = self.expect(map)
		if result is None:
			raise Exception('Unexpected result: \n' + self.buffer)
		else:
			return result

	def exit(self):
		self.proc.stdout.flush()
		self.proc.stderr.flush()
		self.proc.terminate()

	def dump(self):
		self.read()
		print(self.buffer)


class _Getch:
	"""Gets a single character from standard input.  Does not echo to the
screen."""
	def __init__(self):
		try:
			self.impl = _GetchWindows()
		except ImportError:
			self.impl = _GetchUnix()

	def __call__(self): return self.impl()


class _GetchUnix:
	def __init__(self):
		import tty, sys

	def __call__(self):
		import sys, tty, termios
		fd = sys.stdin.fileno()
		old_settings = termios.tcgetattr(fd)
		try:
			tty.setraw(sys.stdin.fileno())
			ch = sys.stdin.read(1)
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
		return ch


class _GetchWindows:
	def __init__(self):
		import msvcrt

	def __call__(self):
		import msvcrt
		return msvcrt.getch()

getch = _Getch()

import platform
from enum import Enum


class OS(Enum):
	Unknown = 'Unknown'
	Mac = 'Mac'
	Linux = 'Linux'
	Windows = 'Windows'

	@staticmethod
	def type():
		return {
			'Darwin': OS.Mac,
			'Linux': OS.Linux,
			'Windows': OS.Windows,
		}.get(platform.system(), OS.Unknown)


from pathlib import Path


class Utils:
	@staticmethod
	def directory_size(dir: str):
		path = Path(dir)
		return sum(path.stat().st_blocks
				   for f in path.glob('**/*') if f.is_file()) * path.stat().st_blksize

	@staticmethod
	def round_up_power_of_2(n: int):
		return 1 << (n-1).bit_length()

import argparse

def dir_path(string):
	if os.path.isdir(string):
		return os.path.abspath(string)
	else:
		raise argparse.ArgumentTypeError(f'`{string}` is not a directory')


def file_path(string):
	if os.path.isfile(string):
		return os.path.abspath(string)
	else:
		raise argparse.ArgumentTypeError(f'`{string}` is not a file')


def new_file(string):
	try:
		open(string, 'w+').close()
	except OSError as e:
		raise e
	return os.path.abspath(string)


def c_identifier(string):
	pattern = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')
	if not pattern.match(string):
		raise argparse.ArgumentTypeError(f'`{string}` is not a valid c identifier')
	return string


def check_args(args: argparse.Namespace, *required):
	v = vars(args)
	required_values = [v[f] for f in required]
	if None in required_values:
		absent = [i for i, x in enumerate(required_values) if x is None]
		Msg.panic('argument ' + ', '.join(f'`{required[x]}`' for x in absent) +
				  f'is required for {os.path.basename(sys.modules["__main__"].__file__)}')
