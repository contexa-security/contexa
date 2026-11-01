"""ux_keys.py behind a file lock, for several writers at once (UX-R1 I-10 DEC-82: parallel restoration groups).

    python -I ux_keys_locked.py keys.json [--check]

The dictionaries are read, changed and written whole; two writers at the same moment would lose one's keys. This waits
for the lock (a byte of `.ux_keys.lock` locked with msvcrt, released when the process ends), then runs ux_keys.py.
"""
import msvcrt
import pathlib
import runpy
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
LOCK = HERE / '.ux_keys.lock'


def main():
    with open(LOCK, 'a+b') as handle:
        for _ in range(300):
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                time.sleep(1)
        else:
            sys.exit('ux_keys lock not taken in 300 s')
        try:
            sys.argv = [str(HERE / 'ux_keys.py'), *sys.argv[1:]]
            runpy.run_path(str(HERE / 'ux_keys.py'), run_name='__main__')
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == '__main__':
    main()
