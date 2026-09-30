// Frida hook: dump all HID traffic on HECATE GX03 dongle handles (VID_35BB)
// inside the vendor app. Tracks CreateFileW paths, then hooks HidD_SetFeature,
// HidD_GetFeature, WriteFile, ReadFile filtered by tracked handles.
// HID.dll hooks are installed lazily on first matching open (the DLL is not
// necessarily mapped when the script loads).

const tracked = {}; // handle string -> device path
let hidHooked = false;

function isOurs(path) {
  return path && path.indexOf('VID_35BB') !== -1;
}

function globalExport(name) {
  try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
}

Interceptor.attach(globalExport('CreateFileW'), {
  onEnter(args) {
    try { this.path = args[0].readUtf16String(); } catch (e) { this.path = null; }
  },
  onLeave(retval) {
    if (isOurs(this.path) && !retval.isNull() && retval.toInt32() !== -1) {
      tracked[retval.toString()] = this.path;
      send({ t: 'open', h: retval.toString(), p: this.path });
      if (!hidHooked) { hidHooked = true; hookHid(); }
    }
  }
});

Interceptor.attach(globalExport('CloseHandle'), {
  onEnter(args) {
    const h = args[0].toString();
    if (tracked[h] !== undefined) delete tracked[h];
  }
});

function hookHid() {
  ['HidD_SetFeature', 'HidD_GetFeature'].forEach(function (fn) {
    const addr = globalExport(fn);
    if (!addr) { send({ t: 'warn', m: 'missing ' + fn }); return; }
    Interceptor.attach(addr, {
      onEnter(args) {
        this.h = args[0].toString();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.ours = tracked[this.h] !== undefined;
        if (this.ours && fn === 'HidD_SetFeature' && this.len > 0) {
          send({ t: 'SET_FEATURE', h: this.h, len: this.len }, this.buf.readByteArray(this.len));
        }
      },
      onLeave(retval) {
        if (!this.ours) return;
        if (fn === 'HidD_GetFeature' && !retval.isNull() && this.len > 0) {
          send({ t: 'GET_FEATURE', h: this.h, len: this.len }, this.buf.readByteArray(this.len));
        }
      }
    });
  });
  send({ t: 'hid-hooks-installed' });
}

// DeviceIoControl (hidapi.dll uses this for feature reports)
Interceptor.attach(globalExport('DeviceIoControl'), {
  onEnter(args) {
    this.h = args[0].toString();
    this.code = args[1].toInt32() >>> 0;
    this.inBuf = args[2];
    this.inLen = args[3].toInt32();
    this.outBuf = args[4];
    this.brp = args[6];
    this.ours = tracked[this.h] !== undefined;
    if (this.ours && this.inLen > 0) {
      send({ t: 'IOCTL_IN', h: this.h, code: '0x' + this.code.toString(16), len: this.inLen }, this.inBuf.readByteArray(this.inLen));
    }
  },
  onLeave(retval) {
    if (!this.ours || retval.isNull()) return;
    let n = 0;
    try { if (!this.brp.isNull()) n = this.brp.readU32(); } catch (e) { n = 0; }
    if (n > 0 && n <= 512) {
      send({ t: 'IOCTL_OUT', h: this.h, code: '0x' + this.code.toString(16), len: n }, this.outBuf.readByteArray(n));
    }
  }
});

['WriteFile', 'ReadFile'].forEach(function (fn) {
  Interceptor.attach(globalExport(fn), {
    onEnter(args) {
      this.h = args[0].toString();
      this.buf = args[1];
      this.ours = tracked[this.h] !== undefined;
      this.countPtr = args[3];
      this.ov = args[7];
    },
    onLeave(retval) {
      if (!this.ours) return;
      let n = 0;
      try {
        if (!this.countPtr.isNull()) n = this.countPtr.readU32();
        else if (!this.ov.isNull()) n = this.ov.add(8).readU64().toNumber();
      } catch (e) { n = 0; }
      if (n > 0 && n <= 512) {
        send({ t: fn === 'WriteFile' ? 'WRITE' : 'READ', h: this.h, len: n }, this.buf.readByteArray(n));
      }
    }
  });
});

send({ t: 'hooks-installed' });
