#!/usr/bin/python

'''Python Library/cli for providing a higher level interface to flock(2)'''

__version__ = '0.0.0'


__all__ = ('take_lock', 'release_lock', 'lockfile')


from contextlib import contextmanager
from errno import EINTR, EAGAIN, EBADF
from fcntl import flock, LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN
from multiprocessing import Pipe, Process
import os
from os import strerror
from signal import signal, SIGALRM, setitimer, ITIMER_REAL
from sys import exit


def _set_alarm_and_lock(fd, pipew, timeout, shared):
	try:
		# TODO: How can you deal with the race where the signal could
		# be delivered before you lock, so instead of being woken up
		# when the signal is delivered, we block forever.
		signal(SIGALRM, lambda *_: None)
		setitimer(ITIMER_REAL, timeout)
		flock(fd, LOCK_SH if shared else LOCK_EX)
	except BaseException as e:
		# This loses the traceback, but it's not pickleable anyway
		pipew.send(e)
		exit(1)
	else:
		pipew.send(None)
		exit(0)


def take_lock(fd, timeout=None, shared=False):
	'''Take a lock on a file descriptor

	If timeout is 0 the lock is taken without blocking,
	if timeout is None we block indefinitely,
	if timeout is a positive number we time out in that many seconds.

	If shared is True this is a shared lock,
	so can lock with other shared locks,
	if shared is False this is an exclusive lock.

	with open(path, 'r') as lock:
		take_lock(lock.fileno(), timeout, shared)

	'''
	if timeout is None or timeout == 0:
		flags = (LOCK_SH if shared else LOCK_EX)
		flags |= (LOCK_NB if timeout == 0 else 0)
		flock(fd, flags)
		return
	piper, pipew = Pipe(duplex=False)
	p = Process(target=_set_alarm_and_lock,
	            args=(fd, pipew, timeout, shared))
	p.start()
	err = piper.recv()
	p.join()
	if err:
		if isinstance(err, IOError) and err.errno == EINTR:
			raise IOError(EAGAIN, strerror(EAGAIN))
		raise err


def release_lock(fd):
	'''Release a lock on a file descriptor

	release_lock(lock.fileno())

	'''
	return flock(fd, LOCK_UN)


class _Lockfile(object):
	def __init__(self, fd):
		self.fd = fd
	def lock(self, *args, **kwargs):
		return take_lock(self.fd, *args, **kwargs)
	def unlock(self):
		return flock(self.fd, LOCK_UN)


@contextmanager
def lockfile(path):
	'''Context manager for lock files.

	with lockfile(path) as lockfobj:
		lockfobj.lock(timeout=0, shared=False)
	

	'''
	fd = os.open(path, os.O_RDONLY)
	lockfobj = _Lockfile(fd)
	try:
		yield lockfobj
	finally:
		# Handle double-close of file descriptor
		try:
			os.close(fd)
		except OSError as e:
			if e.errno != EBADF:
				raise


if __name__ == '__main__':
	from argparse import ArgumentParser
	from subprocess import call

	parser = ArgumentParser(description=__doc__)
	parser.add_argument('--version', action='version',
	                    version=('%(prog)s ' + __version__))
	parser.add_argument('--shared', action='store_true', default=False)
	parser.add_argument('--exclusive', dest='shared', action='store_false')
	parser.add_argument('--timeout', default=None, type=int)
	parser.add_argument('--wait', dest='timeout', action='store_const', const=None)
	parser.add_argument('--nonblock', dest='timeout', action='store_const', const=0)
	parser.add_argument('file')
	parser.add_argument('argv', nargs='*')

	opts = parser.parse_args()

	if len(opts.argv) == 0:
		fd = int(opts.file)
		take_lock(fd, opts.timeout, opts.shared)
	else:
		with lockfile(opts.file) as lock:
			lock.lock(timeout=opts.timeout, shared=opts.shared)
			exit(call(opts.argv))
