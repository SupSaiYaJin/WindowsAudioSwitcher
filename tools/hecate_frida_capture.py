"""Frida capture driver: restart HECATE.exe under Frida and dump all dongle HID
traffic to stdout (and a log file) with timestamps.

Usage: python hecate_frida_capture.py [seconds]

Requires: pip install frida ; HECATE.exe at D:\\Software\\HECATE\\HECATE.exe
The running elevated HECATE instance must be closed first (asInvoker app, safe
to restart without elevation).
"""
import datetime
import pathlib
import sys
import time

import frida

APP = r'D:\Software\HECATE\HECATE.exe'
HERE = pathlib.Path(__file__).parent
LOG = HERE / 'hecate_capture.log'


def ts():
    return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]


def on_message(message, data):
    if message.get('type') == 'send':
        payload = message['payload']
        line = f'[{ts()}] {payload}'
        if data:
            line += '  DATA ' + bytes(data).hex(' ')
        print(line, flush=True)
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    else:
        print(f'[{ts()}] frida: {message}', flush=True)


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 45
    device = frida.get_local_device()
    target = None
    for p in device.enumerate_processes():
        if p.name.lower() == 'hecate.exe':
            target = p.pid
    if target is None:
        pid = device.spawn([APP])
        print(f'spawned pid={pid}', flush=True)
        session = device.attach(pid)
        resume_needed = True
    else:
        pid = target
        print(f'attaching to running pid={pid}', flush=True)
        session = device.attach(pid)
        resume_needed = False
    script = session.create_script((HERE / 'hecate_frida_hook.js').read_text(encoding='utf-8'))
    script.on('message', on_message)
    script.load()
    if resume_needed:
        device.resume(pid)
    print(f'capturing {dur}s ...', flush=True)
    deadline = time.time() + dur
    while time.time() < deadline:
        time.sleep(0.5)
    print('capture done', flush=True)


if __name__ == '__main__':
    main()
