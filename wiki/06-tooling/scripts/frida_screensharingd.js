'use strict';

const MODE = '__MODE__';
const STATIC_BASE = ptr('0x100000000');

function hex(v) {
  return ptr(v).toString();
}

function log(name, fields) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    mode: MODE,
    name,
    ...fields,
  }));
}

function stripCodePac(p) {
  try {
    if (p === null || p === undefined) return p;
    if (typeof p.strip === 'function') return p.strip('ia');
  } catch (_) {
  }
  return p;
}

function toHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function readVolatileCompat(p, size) {
  if (p !== null && p !== undefined && typeof p.readVolatile === 'function') {
    return p.readVolatile(size);
  }
  if (typeof Memory.readVolatile === 'function') {
    return Memory.readVolatile(p, size);
  }
  throw new Error('readVolatile unavailable');
}

function dataPtrCandidates(p) {
  const out = [];
  if (p === null || p === undefined) return out;
  out.push({ mode: 'raw', ptr: p });
  try {
    if (typeof p.strip === 'function') {
      const da = p.strip('da');
      if (!da.equals(p)) out.push({ mode: 'da', ptr: da });
      const db = p.strip('db');
      if (!db.equals(p) && !db.equals(da)) out.push({ mode: 'db', ptr: db });
    }
  } catch (_) {
  }
  return out;
}

function readBytesDetailed(basePtr, size) {
  const errors = [];
  for (const candidate of dataPtrCandidates(basePtr)) {
    try {
      return { hex: toHex(Memory.readByteArray(candidate.ptr, size)), mode: candidate.mode, error: null };
    } catch (e1) {
      errors.push(`${candidate.mode}: ${String(e1)}`);
    }
    try {
      return { hex: toHex(readVolatileCompat(candidate.ptr, size)), mode: `${candidate.mode}_volatile`, error: null };
    } catch (e2) {
      errors.push(`${candidate.mode}_volatile: ${String(e2)}`);
    }
  }
  return { hex: null, mode: null, error: errors.join(' | ') || null };
}

function readPointerDetailed(basePtr) {
  const errors = [];
  for (const candidate of dataPtrCandidates(basePtr)) {
    try {
      let value = null;
      if (candidate.ptr !== null && candidate.ptr !== undefined && typeof candidate.ptr.readPointer === 'function') {
        value = candidate.ptr.readPointer();
      } else {
        value = Memory.readPointer(candidate.ptr);
      }
      return { value, mode: candidate.mode, error: null };
    } catch (e) {
      errors.push(`${candidate.mode}: ${String(e)}`);
    }
  }
  return { value: null, mode: null, error: errors.join(' | ') || null };
}

function readU8Safe(p) {
  try { return Memory.readU8(p); } catch (_) { return null; }
}
function readU32Safe(p) {
  try { return Memory.readU32(p); } catch (_) { return null; }
}

const mainModule = Process.enumerateModules().find(m => m.name === 'screensharingd');
if (mainModule === undefined) {
  throw new Error('screensharingd base not found');
}
const base = mainModule.base;
log('module', { base: hex(base) });

function installSrpKeyHooks() {
  const srpShaReturn = base.add(ptr('0x100019264').sub(STATIC_BASE));
  const setupAesReturns = [
    base.add(ptr('0x10001700c').sub(STATIC_BASE)),
    base.add(ptr('0x1000170b8').sub(STATIC_BASE)),
    base.add(ptr('0x100017160').sub(STATIC_BASE)),
    base.add(ptr('0x100017240').sub(STATIC_BASE)),
  ];
  const shaStub = base.add(ptr('0x100076f18').sub(STATIC_BASE));
  const cryptorStub = base.add(ptr('0x100076e78').sub(STATIC_BASE));
  Interceptor.attach(shaStub, {
    onEnter(args) {
      const ret = stripCodePac(this.returnAddress);
      if (!ret.equals(srpShaReturn)) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.dataPtr = args[0];
      this.len = Number(args[1]);
      this.outPtr = args[2];
      const inputRead = readBytesDetailed(this.dataPtr, Math.min(this.len, 64));
      log('srp_sha256_enter', {
        return_to: hex(ret),
        len: this.len,
        input_head_64: inputRead.hex,
        input_read_mode: inputRead.mode,
      });
    },
    onLeave(retval) {
      if (this.skip) return;
      const digestRead = readBytesDetailed(this.outPtr, 32);
      const keyRead = readBytesDetailed(this.outPtr, 16);
      log('srp_sha256_done', {
        return_value: Number(retval),
        sha256_digest: digestRead.hex,
        session_key_16: keyRead.hex,
      });
    }
  });
  Interceptor.attach(cryptorStub, {
    onEnter(args) {
      const ret = stripCodePac(this.returnAddress);
      if (!setupAesReturns.some(addr => ret.equals(addr))) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.returnTo = ret;
      this.op = Number(args[0]);
      this.alg = Number(args[1]);
      this.options = Number(args[2]);
      this.keyPtr = args[3];
      this.keyLen = Number(args[4]);
      this.ivPtr = args[5];
      this.cryptorRefPtr = args[6];
      log('setup_aes_keys_enter', {
        return_to: hex(this.returnTo),
        op: this.op,
        alg: this.alg,
        options: this.options,
        session_key: readBytesDetailed(this.keyPtr, this.keyLen > 0 ? Math.min(this.keyLen, 32) : 16).hex,
        iv_16: this.ivPtr.isNull() ? null : readBytesDetailed(this.ivPtr, 16).hex,
      });
    },
    onLeave(retval) {
      if (this.skip) return;
      const cryptorPtrRead = this.cryptorRefPtr.isNull() ? null : readPointerDetailed(this.cryptorRefPtr);
      log('setup_aes_keys_done', {
        return_to: hex(this.returnTo),
        status: Number(retval),
        cryptor_ptr: cryptorPtrRead && cryptorPtrRead.value ? hex(cryptorPtrRead.value) : null,
      });
    }
  });
}

function installTransportHooks() {
  const shaStub = base.add(ptr('0x100076f18').sub(STATIC_BASE));
  const cryptorUpdateStub = base.add(ptr('0x100076e98').sub(STATIC_BASE));
  const cryptorCreateStub = base.add(ptr('0x100076e78').sub(STATIC_BASE));
  const srpShaReturn = base.add(ptr('0x100019264').sub(STATIC_BASE));
  const encinfoUpdateReturns = [
    base.add(ptr('0x100021e6c').sub(STATIC_BASE)),
    base.add(ptr('0x100021e98').sub(STATIC_BASE)),
  ];
  const encinfoCreateReturns = [
    base.add(ptr('0x100021ef0').sub(STATIC_BASE)),
    base.add(ptr('0x100021fac').sub(STATIC_BASE)),
    base.add(ptr('0x100022060').sub(STATIC_BASE)),
    base.add(ptr('0x100022114').sub(STATIC_BASE)),
    base.add(ptr('0x100022250').sub(STATIC_BASE)),
  ];
  const traceState = { initialWrapKeyHex: null };
  Interceptor.attach(shaStub, {
    onEnter(args) {
      const ret = stripCodePac(this.returnAddress);
      if (!ret.equals(srpShaReturn)) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.outPtr = args[2];
    },
    onLeave(retval) {
      if (this.skip) return;
      traceState.initialWrapKeyHex = readBytesDetailed(this.outPtr, 16).hex;
      log('srp_sha256_done', { return_value: Number(retval), initial_wrap_key_16: traceState.initialWrapKeyHex });
    }
  });
  Interceptor.attach(cryptorUpdateStub, {
    onEnter(args) {
      const ret = stripCodePac(this.returnAddress);
      const idx = encinfoUpdateReturns.findIndex(addr => ret.equals(addr));
      if (idx === -1) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.blockIndex = idx + 1;
      this.dataIn = args[1];
      this.dataInLen = Number(args[2]);
      this.dataOut = args[3];
      this.dataOutAvail = Number(args[4]);
      this.dataOutMovedPtr = args[5];
      log('encinfo_update_enter', {
        block_index: this.blockIndex,
        initial_wrap_key_16: traceState.initialWrapKeyHex,
        plaintext_head: readBytesDetailed(this.dataIn, Math.min(this.dataInLen, 64)).hex,
      });
    },
    onLeave(retval) {
      if (this.skip) return;
      const moved = this.dataOutMovedPtr.isNull() ? null : readU32Safe(this.dataOutMovedPtr);
      log('encinfo_update_done', {
        block_index: this.blockIndex,
        status: Number(retval),
        out_len: moved,
        ciphertext_head: readBytesDetailed(this.dataOut, Math.min(moved || this.dataOutAvail, 64)).hex,
      });
    }
  });
  Interceptor.attach(cryptorCreateStub, {
    onEnter(args) {
      const ret = stripCodePac(this.returnAddress);
      if (!encinfoCreateReturns.some(addr => ret.equals(addr))) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.keyPtr = args[3];
      this.keyLen = Number(args[4]);
      this.ivPtr = args[5];
    },
    onLeave(retval) {
      if (this.skip) return;
      log('encinfo_create_done', {
        status: Number(retval),
        key_hex: this.keyLen > 0 ? readBytesDetailed(this.keyPtr, Math.min(this.keyLen, 32)).hex : null,
        iv_hex: this.ivPtr.isNull() ? null : readBytesDetailed(this.ivPtr, 16).hex,
      });
    }
  });
}

function installHpHooks() {
  const probes = [
    { name: 'hp_set_encodings_enter', staticAddr: ptr('0x1000377c0') },
    { name: 'hp_encoding_scan_loop', staticAddr: ptr('0x100037984') },
    { name: 'hp_chosen_encoding', staticAddr: ptr('0x10003b3ec') },
    { name: 'hp_promode_viewer', staticAddr: ptr('0x10003b67c') },
    { name: 'hp_gate_checks', staticAddr: ptr('0x10003b700') },
    { name: 'hp_init_video_flag', staticAddr: ptr('0x10003bab4') },
    { name: 'hp_codec_change', staticAddr: ptr('0x10003bb3c') },
    { name: 'hp_avc_stream_active', staticAddr: ptr('0x10003f1a8') },
    { name: 'hp_media_stream_error', staticAddr: ptr('0x10003f310') },
  ];
  probes.forEach(probe => {
    const runtime = base.add(probe.staticAddr.sub(STATIC_BASE));
    log('probe_install', { probe: probe.name, runtime: hex(runtime) });
    Interceptor.attach(runtime, {
      onEnter(args) {
        log('hp_probe_hit', {
          probe: probe.name,
          pc: hex(this.context.pc),
          x0: hex(args[0]),
          x1: hex(args[1]),
          x2: hex(args[2]),
          x3: hex(args[3]),
          x0_u8: readU8Safe(args[0]),
          x0_u32: readU32Safe(args[0]),
        });
      }
    });
  });
}

if (MODE === 'transport') {
  installTransportHooks();
} else if (MODE === 'srpkey') {
  installSrpKeyHooks();
} else if (MODE === 'hp') {
  installHpHooks();
} else {
  log('unknown_mode', { mode: MODE });
}
