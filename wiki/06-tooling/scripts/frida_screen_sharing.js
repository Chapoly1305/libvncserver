'use strict';

const MODE = '__MODE__';
const AUTH_REWRITE_TYPES = [__AUTH_TYPES__];

function hex(v) {
  return ptr(v).toString();
}

function now() {
  return new Date().toISOString();
}

function log(name, fields) {
  console.log(JSON.stringify({
    ts: now(),
    mode: MODE,
    name,
    ...fields,
  }));
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
    return Memory.readVolatile(ptr(p), size);
  }
  throw new Error('readVolatile unavailable');
}

function readBytes(p, size) {
  try {
    return toHex(Memory.readByteArray(ptr(p), size));
  } catch (_) {
    try {
      return toHex(readVolatileCompat(ptr(p), size));
    } catch (_) {
      return null;
    }
  }
}

function readU64(p) {
  try {
    return ptr(p).readU64().toString();
  } catch (_) {
    return null;
  }
}

function moduleNameFromAddr(addr) {
  try {
    const m = Process.findModuleByAddress(ptr(addr));
    if (!m) return null;
    return { name: m.name, path: m.path, base: hex(m.base) };
  } catch (_) {
    return null;
  }
}

function interestingCaller(ret) {
  const m = moduleNameFromAddr(ret);
  if (!m) return null;
  if (m.path.indexOf('Screen Sharing.app/Contents/MacOS/Screen Sharing') !== -1) return m;
  if (m.path.indexOf('ScreenSharing.framework') !== -1) return m;
  return null;
}

function findExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      return Module.findGlobalExportByName(name);
    }
  } catch (_) {
  }
  try {
    if (typeof Module.getGlobalExportByName === 'function') {
      return Module.getGlobalExportByName(name);
    }
  } catch (_) {
  }
  try {
    if (typeof Module.findExportByName === 'function') {
      return Module.findExportByName(null, name);
    }
  } catch (_) {
  }
  return null;
}

function methodExists(className, selector) {
  return !!(ObjC.available && ObjC.classes[className] && ObjC.classes[className][selector]);
}

function installForcedReturn(className, selector, retval) {
  if (!methodExists(className, selector)) {
    log('probe_missing', { class_name: className, selector });
    return;
  }
  const method = ObjC.classes[className][selector];
  log('probe_install', {
    class_name: className,
    selector,
    implementation: hex(method.implementation),
    forced_retval: retval,
  });
  Interceptor.attach(method.implementation, {
    onEnter(args) {
      this.selfPtr = hex(args[0]);
      this.tid = Process.getCurrentThreadId();
    },
    onLeave(retvalObj) {
      const original = retvalObj.toString();
      retvalObj.replace(ptr(retval));
      log('forced_return', {
        class_name: className,
        selector,
        thread_id: this.tid,
        self_ptr: this.selfPtr,
        original_retval: original,
        forced_retval: retval,
      });
    },
  });
}

function installDynamicProbe(className, selector) {
  if (!methodExists(className, selector)) {
    log('probe_missing', { class_name: className, selector });
    return;
  }
  const method = ObjC.classes[className][selector];
  Interceptor.attach(method.implementation, {
    onEnter(args) {
      this.selfPtr = hex(args[0]);
      const arg2 = args[2] ? args[2].toInt32() : null;
      log('dynamic_probe_enter', {
        class_name: className,
        selector,
        self_ptr: this.selfPtr,
        arg2,
      });
    },
    onLeave(retval) {
      log('dynamic_probe_leave', {
        class_name: className,
        selector,
        retval: retval.toString(),
      });
    },
  });
}

function nsArrayToDescriptions(obj) {
  const out = [];
  try {
    const count = obj.count().valueOf();
    for (let i = 0; i < count; i++) {
      const item = new ObjC.Object(obj.objectAtIndex_(i));
      out.push(item.toString());
    }
  } catch (_) {
  }
  return out;
}

function mapAuthTypeToName(n) {
  switch (n) {
    case 30:
      return 'DiffieHellmanNamePassword';
    case 31:
      return 'GuestObserve';
    case 32:
      return 'GuestControl';
    case 33:
      return 'RSA';
    case 34:
      return 'Kerberos';
    case 35:
      return 'SRP';
    case 36:
      return 'SRP';
    default:
      return null;
  }
}

function buildNSStringArray(names) {
  const NSString = ObjC.classes.NSString;
  const NSMutableArray = ObjC.classes.NSMutableArray;
  const arr = NSMutableArray.alloc().init();
  names.forEach(name => arr.addObject_(NSString.stringWithString_(name)));
  return arr;
}

function isForcedSingleAuthType(n) {
  return AUTH_REWRITE_TYPES.length === 1 && AUTH_REWRITE_TYPES[0] === n;
}

function findScreenSharingFrameworkModule() {
  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {
    if (modules[i].path.indexOf('ScreenSharing.framework') !== -1) {
      return modules[i];
    }
  }
  return null;
}

function runtimeAddressFromBn(bnAddress) {
  if (!ObjC.available || !methodExists('SSSession', '- doesServerSupportProMode')) {
    return null;
  }
  const liveImpl = ObjC.classes.SSSession['- doesServerSupportProMode'].implementation;
  const bnImpl = ptr('0x1c212e4d0');
  const slide = ptr(liveImpl).sub(bnImpl);
  return ptr(bnAddress).add(slide);
}

function installRawSecurityTypesRewriteHook() {
  const rewrittenTypes = AUTH_REWRITE_TYPES.filter(n => Number.isInteger(n) && n >= 0 && n <= 255);
  log('raw_auth_rewrite_config', { rewritten_types: rewrittenTypes });
  if (rewrittenTypes.length === 0) return;

  const framework = findScreenSharingFrameworkModule();
  if (!framework) {
    log('raw_auth_rewrite_error', { error: 'ScreenSharing.framework module not found' });
    return;
  }

  const readSocketData = runtimeAddressFromBn('0x1c20bd1a4');
  const secondReadReturn = runtimeAddressFromBn('0x1c20bff50');
  if (readSocketData === null || secondReadReturn === null) {
    log('raw_auth_rewrite_error', { error: 'failed to derive runtime addresses from BN anchors' });
    return;
  }
  log('raw_auth_rewrite_install', {
    module_base: hex(framework.base),
    readsocketdata: hex(readSocketData),
    second_read_return: hex(secondReadReturn),
  });

  let readSocketLogCount = 0;
  Interceptor.attach(readSocketData, {
    onEnter(args) {
      if (readSocketLogCount >= 8) return;
      const ret = this.returnAddress;
      if (ret.compare(framework.base) < 0 || ret.compare(framework.base.add(framework.size)) >= 0) return;
      readSocketLogCount += 1;
      log('readsocketdata_call', {
        idx: readSocketLogCount,
        return_address: hex(ret),
        return_offset: hex(ret.sub(framework.base)),
        session_ptr: hex(args[0]),
        dst_ptr: hex(args[1]),
        len: args[2].toInt32(),
      });
    },
  });

  Interceptor.attach(secondReadReturn, {
    onEnter() {
      try {
        if (this.context.x0.toInt32() !== 0) return;

        const session = ptr(this.context.x19);
        const countPtr = session.add(0xa20);
        const listPtr = session.add(0xa21);
        const originalCount = countPtr.readU8();
        const originalTypes = [];
        const readCount = Math.min(originalCount, 50);
        for (let i = 0; i < readCount; i++) {
          originalTypes.push(listPtr.add(i).readU8());
        }

        countPtr.writeU8(rewrittenTypes.length);
        for (let i = 0; i < rewrittenTypes.length; i++) {
          listPtr.add(i).writeU8(rewrittenTypes[i]);
        }
        for (let i = rewrittenTypes.length; i < readCount; i++) {
          listPtr.add(i).writeU8(0);
        }

        log('raw_auth_rewrite_applied', {
          session_ptr: hex(session),
          original_count: originalCount,
          original_types: originalTypes,
          rewritten_count: rewrittenTypes.length,
          rewritten_types: rewrittenTypes,
        });
      } catch (e) {
        log('raw_auth_rewrite_error', { error: String(e) });
      }
    },
  });
}

function installAuthRewriteHook() {
  if (!ObjC.available) return;
  const selector = '- ssSession:wantsCredentialsForAuthenticationTypes:';
  if (!methodExists('SSSessionView', selector)) {
    log('probe_missing', { class_name: 'SSSessionView', selector });
    return;
  }
  const rewrittenTypes = AUTH_REWRITE_TYPES.filter(n => Number.isInteger(n) && n >= 0 && n <= 255);
  const rewrittenNames = rewrittenTypes.map(mapAuthTypeToName).filter(name => name !== null);
  log('auth_rewrite_config', { rewritten_types: rewrittenTypes });
  const method = ObjC.classes.SSSessionView[selector];
  const originalImpl = new NativeFunction(method.implementation, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
  const replacement = ObjC.implement(method, function(self, _cmd, session, authTypes) {
    let original = null;
    let originalClass = null;
    let originalDesc = null;
    let items = [];
    try {
      const originalObj = new ObjC.Object(authTypes);
      original = nsArrayToDescriptions(originalObj);
      originalClass = originalObj.$className;
      originalDesc = originalObj.toString();
      try {
        const count = originalObj.count().valueOf();
        for (let i = 0; i < count; i++) {
          const item = new ObjC.Object(originalObj.objectAtIndex_(i));
          items.push({
            class_name: item.$className,
            description: item.toString(),
          });
        }
      } catch (_) {
      }
    } catch (e) {
      log('auth_rewrite_error', { stage: 'decode', error: String(e) });
    }

    log('auth_rewrite_enter', {
      self_ptr: hex(self),
      original_class: originalClass,
      original_description: originalDesc,
      original_types: original,
      original_items: items,
      rewritten_types: rewrittenTypes,
      rewritten_items: rewrittenNames,
    });

    if (isForcedSingleAuthType(33)) {
      try {
        const selfObj = new ObjC.Object(self);
        const sessionObj = new ObjC.Object(session);
        const manager = ObjC.classes.SSCredentialsManager.sharedManager();
        const options = sessionObj.connectionOptions();
        manager.requestCredentialsForRSAForRequester_withOptions_(selfObj, options);
        log('auth33_policy_bypass', {
          self_ptr: hex(self),
          session_ptr: hex(session),
          options_ptr: hex(options ? options.handle || options : ptr(0)),
          original_types: original,
        });
        return;
      } catch (e) {
        log('auth_rewrite_error', { stage: 'auth33_policy_bypass', error: String(e) });
      }
    }

    if (rewrittenNames.length > 0) {
      try {
        const replacementArray = buildNSStringArray(rewrittenNames);
        originalImpl(self, _cmd, session, replacementArray.handle);
        return;
      } catch (e) {
        log('auth_rewrite_error', { stage: 'replacement_call', error: String(e) });
      }
    }

    originalImpl(self, _cmd, session, authTypes);
  });
  log('auth_rewrite_install', {
    selector,
    implementation: hex(method.implementation),
    replacement: hex(replacement),
  });
}

function installKerberosPreferenceBypassHook() {
  if (!ObjC.available || !isForcedSingleAuthType(33)) return;
  const selector = '- shouldPreferKerberosWithAuthTypes:wasBTMM:';
  if (!methodExists('SSSessionView', selector)) {
    log('probe_missing', { class_name: 'SSSessionView', selector });
    return;
  }
  const method = ObjC.classes.SSSessionView[selector];
  log('kerberos_preference_bypass_install', {
    selector,
    implementation: hex(method.implementation),
  });
  Interceptor.attach(method.implementation, {
    onEnter(args) {
      this.selfPtr = hex(args[0]);
      this.originalTypes = null;
      this.wasBTMM = null;
      try {
        const authTypesObj = new ObjC.Object(args[2]);
        this.originalTypes = nsArrayToDescriptions(authTypesObj);
      } catch (_) {
      }
      try {
        this.wasBTMM = ptr(args[3]).toInt32();
      } catch (_) {
      }
    },
    onLeave(retval) {
      const original = retval.toInt32();
      retval.replace(ptr(0));
      log('kerberos_preference_bypass_applied', {
        self_ptr: this.selfPtr,
        original_retval: original,
        forced_retval: 0,
        original_types: this.originalTypes,
        was_btmm: this.wasBTMM,
      });
    },
  });
}

function installOrderedAuthTypesBypassHook() {
  if (!ObjC.available || !isForcedSingleAuthType(33)) return;
  const selector = '- orderedArrayOfAuthTypesForMethod:preferKerberos:serverAllowedTypes:';
  if (!methodExists('SSSessionView', selector)) {
    log('probe_missing', { class_name: 'SSSessionView', selector });
    return;
  }
  const method = ObjC.classes.SSSessionView[selector];
  const forcedArray = buildNSStringArray(['RSA']);
  log('ordered_auth_bypass_install', {
    selector,
    implementation: hex(method.implementation),
    forced_items: ['RSA'],
  });
  Interceptor.attach(method.implementation, {
    onEnter(args) {
      this.selfPtr = hex(args[0]);
      this.preferKerberos = null;
      this.serverAllowedTypes = null;
      try {
        this.preferKerberos = ptr(args[3]).toInt32();
      } catch (_) {
      }
      try {
        const serverAllowedObj = new ObjC.Object(args[4]);
        this.serverAllowedTypes = nsArrayToDescriptions(serverAllowedObj);
      } catch (_) {
      }
      this.keepAlive = forcedArray;
    },
    onLeave(retval) {
      let original = null;
      try {
        original = nsArrayToDescriptions(new ObjC.Object(retval));
      } catch (_) {
      }
      retval.replace(forcedArray.handle);
      log('ordered_auth_bypass_applied', {
        self_ptr: this.selfPtr,
        prefer_kerberos: this.preferKerberos,
        server_allowed_types: this.serverAllowedTypes,
        original_retval: original,
        forced_retval: ['RSA'],
      });
    },
  });
}

function installTransportHooks() {
  const connectPtr = findExport('connect');
  const sendPtr = findExport('send');
  const sendtoPtr = findExport('sendto');
  const writePtr = findExport('write');
  const CCCryptPtr = findExport('CCCrypt');
  const CCCryptorCreatePtr = findExport('CCCryptorCreate');
  const CCCryptorCreateWithModePtr = findExport('CCCryptorCreateWithMode');
  const CCCryptorUpdatePtr = findExport('CCCryptorUpdate');
  const SecKeyEncryptPtr = findExport('SecKeyEncrypt');
  const SecKeyCreateEncryptedDataPtr = findExport('SecKeyCreateEncryptedData');
  let cryptorCreateCount = 0;
  let cryptorUpdateCount = 0;
  let cryptCount = 0;
  const cryptorOps = {};

  function maybeLogSocketWrite(name, retAddr, fd, buf, len) {
    const caller = interestingCaller(retAddr);
    if (!caller) return;
    const preview = len <= 1024 ? len : 64;
    log(name, {
      caller: caller.path,
      return_address: hex(retAddr),
      fd,
      len,
      data_hex: preview > 0 ? readBytes(buf, preview) : '',
      truncated: len > preview,
    });
  }

  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
      },
      onLeave(retval) {
        if (retval.toInt32() === 0) {
          log('socket_connect', { fd: this.fd, retval: retval.toInt32() });
        }
      },
    });
  }
  if (sendPtr) {
    Interceptor.attach(sendPtr, {
      onEnter(args) {
        maybeLogSocketWrite('send', this.returnAddress, args[0].toInt32(), args[1], args[2].toInt32());
      },
    });
  }
  if (sendtoPtr) {
    Interceptor.attach(sendtoPtr, {
      onEnter(args) {
        maybeLogSocketWrite('sendto', this.returnAddress, args[0].toInt32(), args[1], args[2].toInt32());
      },
    });
  }
  if (writePtr) {
    Interceptor.attach(writePtr, {
      onEnter(args) {
        maybeLogSocketWrite('write', this.returnAddress, args[0].toInt32(), args[1], args[2].toInt32());
      },
    });
  }
  if (CCCryptPtr) {
    Interceptor.attach(CCCryptPtr, {
      onEnter(args) {
        this.op = args[0].toInt32();
        this.alg = args[1].toInt32();
        this.options = args[2].toInt32();
        this.keyPtr = args[3];
        this.keyLen = args[4].toInt32();
        this.ivPtr = args[5];
        this.dataIn = args[6];
        this.dataInLen = args[7].toInt32();
        this.dataOut = args[8];
        this.dataOutAvail = args[9].toInt32();
        this.dataOutMoved = args[10];
        this.ret = this.returnAddress;
      },
      onLeave(retval) {
        const caller = interestingCaller(this.ret);
        if (!caller) return;
        cryptCount += 1;
        let moved = null;
        try { moved = Number(readU64(this.dataOutMoved)); } catch (_) {}
        log('cccrypt', {
          idx: cryptCount,
          retval: retval.toInt32(),
          caller: caller.path,
          op: this.op,
          alg: this.alg,
          options: this.options,
          key_len: this.keyLen,
          key_hex: this.keyLen > 0 && this.keyLen <= 32 ? readBytes(this.keyPtr, this.keyLen) : null,
          iv_hex: this.ivPtr.isNull() ? null : readBytes(this.ivPtr, 16),
          data_in_len: this.dataInLen,
          data_out_moved: moved,
        });
      },
    });
  }
  if (CCCryptorCreatePtr) {
    Interceptor.attach(CCCryptorCreatePtr, {
      onEnter(args) {
        this.op = args[0].toInt32();
        this.alg = args[1].toInt32();
        this.options = args[2].toInt32();
        this.keyPtr = args[3];
        this.keyLen = args[4].toInt32();
        this.ivPtr = args[5];
        this.outPtr = args[6];
        this.ret = this.returnAddress;
      },
      onLeave(retval) {
        const caller = interestingCaller(this.ret);
        if (!caller) return;
        cryptorCreateCount += 1;
        let cryptorRef = null;
        try { cryptorRef = hex(Memory.readPointer(this.outPtr)); } catch (_) {}
        if (cryptorRef !== null) {
          cryptorOps[cryptorRef] = { op: this.op, alg: this.alg, options: this.options, caller: caller.path };
        }
        log('cccryptorcreate', {
          idx: cryptorCreateCount,
          retval: retval.toInt32(),
          caller: caller.path,
          op: this.op,
          alg: this.alg,
          options: this.options,
          key_len: this.keyLen,
          key_hex: this.keyLen > 0 && this.keyLen <= 32 ? readBytes(this.keyPtr, this.keyLen) : null,
          iv_hex: this.ivPtr.isNull() ? null : readBytes(this.ivPtr, 16),
          cryptor_ref: cryptorRef,
        });
      },
    });
  }
  if (CCCryptorCreateWithModePtr) {
    Interceptor.attach(CCCryptorCreateWithModePtr, {
      onEnter(args) {
        this.op = args[0].toInt32();
        this.mode = args[1].toInt32();
        this.alg = args[2].toInt32();
        this.padding = args[3].toInt32();
        this.ivPtr = args[4];
        this.keyPtr = args[5];
        this.keyLen = args[6].toInt32();
        this.options = args[9].toInt32();
        this.outPtr = args[13];
        this.ret = this.returnAddress;
      },
      onLeave(retval) {
        const caller = interestingCaller(this.ret);
        if (!caller) return;
        cryptorCreateCount += 1;
        let cryptorRef = null;
        try { cryptorRef = hex(Memory.readPointer(this.outPtr)); } catch (_) {}
        if (cryptorRef !== null) {
          cryptorOps[cryptorRef] = { op: this.op, alg: this.alg, options: this.options, mode: this.mode, caller: caller.path };
        }
        log('cccryptorcreatewithmode', {
          idx: cryptorCreateCount,
          retval: retval.toInt32(),
          caller: caller.path,
          op: this.op,
          mode: this.mode,
          alg: this.alg,
          options: this.options,
          key_len: this.keyLen,
          cryptor_ref: cryptorRef,
        });
      },
    });
  }
  if (CCCryptorUpdatePtr) {
    Interceptor.attach(CCCryptorUpdatePtr, {
      onEnter(args) {
        this.cryptorRef = args[0];
        this.dataInLen = args[2].toInt32();
        this.dataOutMoved = args[5];
        this.ret = this.returnAddress;
      },
      onLeave(retval) {
        const caller = interestingCaller(this.ret);
        if (!caller) return;
        cryptorUpdateCount += 1;
        let moved = null;
        try { moved = Number(readU64(this.dataOutMoved)); } catch (_) {}
        const cryptorMeta = cryptorOps[hex(this.cryptorRef)] || null;
        log('cccryptorupdate', {
          idx: cryptorUpdateCount,
          retval: retval.toInt32(),
          caller: caller.path,
          cryptor_ref: hex(this.cryptorRef),
          cryptor_op: cryptorMeta ? cryptorMeta.op : null,
          cryptor_alg: cryptorMeta ? cryptorMeta.alg : null,
          cryptor_options: cryptorMeta ? cryptorMeta.options : null,
          data_in_len: this.dataInLen,
          data_out_moved: moved,
        });
      },
    });
  }
  if (SecKeyEncryptPtr) {
    Interceptor.attach(SecKeyEncryptPtr, {
      onEnter(args) {
        this.ret = this.returnAddress;
        this.padding = args[1].toInt32();
        this.plainPtr = args[2];
        this.plainLen = args[3].toInt32();
        this.cipherPtr = args[4];
        this.cipherLenPtr = args[5];
      },
      onLeave(retval) {
        const caller = interestingCaller(this.ret);
        if (!caller) return;
        log('seckeyencrypt', {
          retval: retval.toInt32(),
          caller: caller.path,
          padding: this.padding,
          plaintext_len: this.plainLen,
          plaintext_hex: this.plainLen > 0 ? readBytes(this.plainPtr, Math.min(this.plainLen, 256)) : '',
        });
      },
    });
  }
  if (SecKeyCreateEncryptedDataPtr) {
    Interceptor.attach(SecKeyCreateEncryptedDataPtr, {
      onEnter(args) {
        this.ret = this.returnAddress;
        this.algorithm = args[1];
      },
      onLeave(retval) {
        const caller = interestingCaller(this.ret);
        if (!caller) return;
        log('seckeycreateencrypteddata', {
          caller: caller.path,
          algorithm_ptr: hex(this.algorithm),
          retval_ptr: hex(retval),
        });
      },
    });
  }
}

function installForcePromodeHooks() {
  if (!ObjC.available) return;
  installForcedReturn('SSSession', '- displayType', 1);
  installForcedReturn('SSSession', '- doesServerSupportProMode', 1);
  installForcedReturn('SSSession', '- appWantsProModeInterface', 1);
  installForcedReturn('SSEventSession', '- isUsingVirtualDisplay', 1);
  installForcedReturn('SSFrameBufferView', '- isUsingAVCMediaStream', 1);
  installForcedReturn('SSFrameBufferAVConferenceView', '- isUsingAVCMediaStream', 1);
  installForcedReturn('SSSessionView', '- dynamicResolutionModeAvailable', 1);
}

function installDynamicResolutionHooks() {
  if (!ObjC.available) return;
  [
    ['SSSessionView', '- dynamicResolutionModeAvailable'],
    ['SSSessionView', '- setDynamicResolutionMode:'],
    ['SSSessionView', '- ssSessionReady:'],
    ['SSFrameBufferView', '- enteringDynamicResolutionMode'],
    ['SSFrameBufferView', '- isUsingVirtualDisplay'],
  ].forEach(([className, selector]) => installDynamicProbe(className, selector));
}

if (MODE === 'transport') {
  installTransportHooks();
} else if (MODE === 'promode') {
  installForcePromodeHooks();
} else if (MODE === 'promode-transport') {
  installForcePromodeHooks();
  installTransportHooks();
} else if (MODE === 'dynamic-resolution') {
  installDynamicResolutionHooks();
} else if (MODE === 'auth-rewrite') {
  installTransportHooks();
  installRawSecurityTypesRewriteHook();
  installAuthRewriteHook();
  installKerberosPreferenceBypassHook();
  installOrderedAuthTypesBypassHook();
} else {
  log('unknown_mode', { mode: MODE });
}

log('viewer_trace_start', {
  process: Process.enumerateModules()[0].name,
  pid: Process.id,
});
