"""Frida capture v2: inject the HID hook into EVERY HECATE-related process as
they appear (the UI process delegates dongle I/O to a child process).

Usage: python hecate_frida_capture2.py [seconds] [spawn]
  spawn: launch HECATE.exe first (only if none is running)
"""
import datetime
import pathlib
import sys
import time

import frida

APP = r'D:\Software\HECATE\HECATE.exe'
HERE = pathlib.Path(__file__).parent
HOOK = HERE / 'hecate_frida_hook.js'
NAMES = {'hecate.exe', 'updater.exe'}

LOG_PATH = HERE / 'hecate_capture2.log'


def ts():
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]


def make_on_message(pid):
    def on_message(message, data):
        if message.get('type') == 'send':
            payload = message['payload']
            line = f'[{ts()}] pid={pid} {payload}'
            if data:
                line += '  DATA ' + bytes(data).hex(' ')
            print(line, flush=True)
            with open(LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        else:
            print(f'[{ts()}] pid={pid} frida: {message}', flush=True)
    return on_message


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    do_spawn = len(sys.argv) > 2 and sys.argv[2] == 'spawn'
    device = frida.get_local_device()
    hooked = set()

    if do_spawn:
        names = {p.name.lower() for p in device.enumerate_processes()}
        if 'hecate.exe' not in names:
            pid = device.spawn([APP])
            device.resume(pid)
            print(f'[{ts()}] spawned {pid}', flush=True)

    print(f'[{ts()}] watching processes for {dur}s ...', flush=True)
    deadline = time.time() + dur
    while time.time() < deadline:
        try:
            procs = [p for p in device.enumerate_processes() if p.name.lower() in NAMES]
        except Exception as e:
            print(f'[{ts()}] enumerate failed: {e}', flush=True)
            procs = []
        for p in procs:
            if p.pid in hooked:
                continue
            hooked.add(p.pid)
            try:
                session = device.attach(p.pid)
                script = session.create_script(HOOK.read_text(encoding='utf-8'))
                script.on('message', make_on_message(p.pid))
                script.load()
                print(f'[{ts()}] hooked pid={p.pid} ({p.name})', flush=True)
            except Exception as e:
                print(f'[{ts()}] attach {p.pid} failed: {e}', flush=True)
                hooked.discard(p.pid)
        time.sleep(1.0)
    print('capture done', flush=True)


if __name__ == '__main__':
    main()
