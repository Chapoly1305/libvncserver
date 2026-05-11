import datetime
import json
import os

import lldb


TRACE_HANDLE = None
TRACE_PATH = None
BREAKPOINT_META = {}
PATCHED_SELECTORS = set()


TRACE_SPECS = [
    ("manager_open_session_for_connection", "-[SessionControllerManager openSessionForConnection:]", ["x2"]),
    ("manager_close_session_for_connection", "-[SessionControllerManager closeSessionForConnection:]", ["x2"]),
    ("manager_close_open_promode_session", "-[SessionControllerManager closeOpenProModeSession]", []),
    ("window_connect_with_url_options", "-[SessionWindowController connectWithURL:andConnectionOptions:]", ["x2", "x3"]),
    ("viewer_auth_result", "-[SSSessionView ssSession:authenticationResult:]", ["x3"]),
    ("viewer_session_ready", "-[SSSessionView ssSessionReady:]", []),
    ("viewer_should_proceed_vnc", "-[SSSessionView shouldProceedWithVNC]", []),
    ("viewer_dynamic_resolution_available", "-[SSSessionView dynamicResolutionModeAvailable]", []),
    ("viewer_window_restoration_state", "-[SSSessionView windowRestorationStateForWindow:]", ["x2"]),
    ("viewer_virtual_display_state_changed", "-[SSSessionView ssSession:virtualDisplayStateChanged:]", ["x2", "x3"]),
    ("viewer_session_ended", "-[SSSessionView handleSessionEnded:fromID:withInfo:]", ["x2", "x3", "x4"]),
    ("viewer_connect_did_fail", "-[SSSessionView ssSession:connectDidFail:]", ["x2", "x3"]),
    ("viewer_request_updates", "-[SSEventSession requestUpdates]", []),
    ("viewer_keyboard_source_shared", "-[SSEventSession keyboardSourceShared]", []),
    ("viewer_set_keyboard_source_shared", "-[SSEventSession setKeyboardSourceShared:]", ["x2"]),
    ("viewer_is_using_avc_base", "-[SSFrameBufferView isUsingAVCMediaStream]", []),
    ("viewer_is_using_avc_media", "-[SSFrameBufferAVCMediaView isUsingAVCMediaStream]", []),
]

BYPASS_SPECS = [
    ("viewer_session_ended_bypass", "-[SSSessionView handleSessionEnded:fromID:withInfo:]", ["x2", "x3", "x4"]),
    ("viewer_connect_did_fail_bypass", "-[SSSessionView ssSession:connectDidFail:]", ["x2", "x3"]),
    ("viewer_avconference_did_stop", "-[AVConference videoConference:didStopWithCallID:error:callMetadata:]", ["x2", "x3", "x4", "x5"]),
    ("viewer_sessionview_conference_did_stop", "-[SSSessionView conference:didStopWithCallID:error:]", ["x2", "x3", "x4"]),
    ("viewer_start_avconference_call", "-[SSSessionView startAVConferenceCallWithRemoteDictionary:]", ["x2"]),
]

FORCE_SPECS = [
    ("force_display_type", "-[SSSession displayType]", "1"),
    ("force_server_supports_promode", "-[SSSession doesServerSupportProMode]", "1"),
    ("force_app_wants_promode", "-[SSSession appWantsProModeInterface]", "1"),
    ("force_is_using_virtual_display", "-[SSEventSession isUsingVirtualDisplay]", "1"),
    ("force_is_using_avc_base", "-[SSFrameBufferView isUsingAVCMediaStream]", "1"),
    ("force_is_using_avc_avconference", "-[SSFrameBufferAVConferenceView isUsingAVCMediaStream]", "1"),
    ("force_dynamic_resolution_available", "-[SSSessionView dynamicResolutionModeAvailable]", "1"),
]

PATCH_SPECS = [
    ("patch_display_type", "-[SSSession displayType]"),
    ("patch_server_supports_promode", "-[SSSession doesServerSupportProMode]"),
    ("patch_app_wants_promode", "-[SSSession appWantsProModeInterface]"),
    ("patch_is_using_virtual_display", "-[SSEventSession isUsingVirtualDisplay]"),
    ("patch_is_using_avc_base", "-[SSFrameBufferView isUsingAVCMediaStream]"),
    ("patch_is_using_avc_avconference", "-[SSFrameBufferAVConferenceView isUsingAVCMediaStream]"),
    ("patch_dynamic_resolution_available", "-[SSSessionView dynamicResolutionModeAvailable]"),
]

AUTH33_STATIC_ADDRESSES = [
    ("auth_dispatch", 0x100015BDC),
    ("auth_keyreq", 0x100018754),
    ("auth_plain", 0x1000189D4),
    ("auth_srp", 0x100018E8C),
]
AUTH33_AUTO_DISABLE = {"auth_dispatch", "auth_srp"}

HP_STATIC_ADDRESSES = [
    ("hp_set_encodings_enter", 0x1000377C0),
    ("hp_encoding_scan_loop", 0x100037980),
    ("hp_encoding_cmp_3f2", 0x100037990),
    ("hp_encoding_feature_gate", 0x1000379A0),
    ("hp_promode_viewer", 0x10003B67C),
    ("hp_gate_checks", 0x10003B700),
    ("hp_init_video_flag", 0x10003BAB4),
    ("hp_stream_already_active", 0x10003B750),
    ("hp_codec_change", 0x10003BB3C),
    ("hp_avc_stream_active", 0x10003F1A8),
    ("hp_media_stream_error", 0x10003F310),
]
HP_AUTO_DISABLE = {
    "hp_set_encodings_enter",
    "hp_encoding_scan_loop",
    "hp_encoding_cmp_3f2",
    "hp_encoding_feature_gate",
    "hp_promode_viewer",
    "hp_init_video_flag",
    "hp_stream_already_active",
    "hp_codec_change",
}

SRPKEY_STATIC_ADDRESSES = [
    ("srp_keylen", 0x100019240),
    ("srp_sha256", 0x100019260),
    ("srp_install_key", 0x100019274),
    ("setup_aes_keys", 0x100016FB8),
]

PATCH_BYTES = bytes.fromhex("20008052c0035fd6")


def _write_event(event):
    global TRACE_HANDLE
    if TRACE_HANDLE is None:
        return
    TRACE_HANDLE.write(json.dumps(event, sort_keys=True) + "\n")
    TRACE_HANDLE.flush()


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _frame_name(frame):
    return frame.GetDisplayFunctionName() or frame.GetFunctionName() or "<unknown>"


def _reg_value(frame, name):
    reg = frame.FindRegister(name)
    if reg and reg.IsValid():
        return reg.GetValue()
    return None


def _backtrace(thread, limit=4):
    frames = []
    count = min(thread.GetNumFrames(), limit)
    for i in range(count):
        frames.append(_frame_name(thread.GetFrameAtIndex(i)))
    return frames


def _eval_expr(frame, expression):
    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC_plus_plus)
    options.SetIgnoreBreakpoints(True)
    options.SetTrapExceptions(False)
    options.SetTimeoutInMicroSeconds(250000)
    value = frame.EvaluateExpression(expression, options)
    if not value or not value.IsValid() or value.GetError().Fail():
        return None
    return value.GetSummary() or value.GetObjectDescription() or value.GetValue()


def _obj_snapshot(frame, reg_name):
    ptr = _reg_value(frame, reg_name)
    if not ptr or ptr == "0x0000000000000000":
        return None
    expr_prefix = "${}".format(reg_name)
    snapshot = {"ptr": ptr}
    object_value = _eval_expr(frame, "(id){}".format(expr_prefix))
    if object_value:
        snapshot["object"] = object_value
    class_name = _eval_expr(frame, '(id)NSStringFromClass([(id){} class])'.format(expr_prefix))
    if class_name:
        snapshot["class"] = class_name.strip('"')
    description = _eval_expr(frame, "(id)[(id){} description]".format(expr_prefix))
    if description:
        snapshot["description"] = description
    return snapshot


def _prepare_trace(command, result):
    global TRACE_HANDLE, TRACE_PATH, BREAKPOINT_META, PATCHED_SELECTORS
    target = lldb.debugger.GetSelectedTarget()
    if not target or not target.IsValid():
      result.SetError("no valid target")
      return None
    trace_path = command.strip()
    if not trace_path:
      result.SetError("missing trace path")
      return None
    trace_path = os.path.abspath(os.path.expanduser(trace_path))
    os.makedirs(os.path.dirname(trace_path), exist_ok=True)
    if TRACE_HANDLE is not None:
      TRACE_HANDLE.close()
    TRACE_PATH = trace_path
    TRACE_HANDLE = open(trace_path, "a", encoding="utf-8", buffering=1)
    BREAKPOINT_META = {}
    PATCHED_SELECTORS = set()
    return target


def _set_breakpoints(selector_specs, callback_name, result, meta_builder):
    target = lldb.debugger.GetSelectedTarget()
    ci = lldb.debugger.GetCommandInterpreter()
    for spec in selector_specs:
        cmd_result = lldb.SBCommandReturnObject()
        selector = spec[1]
        ci.HandleCommand(f'breakpoint set --name "{selector}"', cmd_result)
        if not cmd_result.Succeeded():
            result.AppendWarning(f"failed to set breakpoint for {selector}: {cmd_result.GetError().strip()}")
            continue
        bp = target.GetBreakpointAtIndex(target.GetNumBreakpoints() - 1)
        if not bp or not bp.IsValid():
            result.AppendWarning(f"breakpoint for {selector} was not retrievable")
            continue
        bp.AddName(spec[0])
        bp.SetScriptCallbackFunction(callback_name)
        meta_builder(bp, spec)
        result.AppendMessage(f"[{bp.GetID()}] {selector}")


def _trace_callback(frame, bp_loc, internal_dict):
    bp = bp_loc.GetBreakpoint()
    meta = BREAKPOINT_META.get(bp.GetID(), {})
    thread = frame.GetThread()
    target = thread.GetProcess().GetTarget()
    pc_addr = frame.GetPCAddress().GetLoadAddress(target)
    event = {
        "ts": _now(),
        "event": "breakpoint_hit",
        "bp_id": bp.GetID(),
        "name": meta.get("name"),
        "selector": meta.get("selector"),
        "function": _frame_name(frame),
        "pc": hex(pc_addr) if pc_addr != lldb.LLDB_INVALID_ADDRESS else None,
        "thread_id": thread.GetThreadID(),
        "backtrace": _backtrace(thread),
    }
    regs = {}
    for reg_name in meta.get("registers", []):
        regs[reg_name] = _reg_value(frame, reg_name)
    if regs:
        event["registers"] = regs
    if meta.get("name") in {"viewer_connect_did_fail", "viewer_session_ended", "viewer_window_restoration_state"}:
        for reg_name in ("x0", "x2", "x3", "x4"):
            snap = _obj_snapshot(frame, reg_name)
            if snap:
                event.setdefault("objects", {})[reg_name] = snap
    _write_event(event)
    return False


def _set_trace(debugger, command, result, internal_dict):
    target = _prepare_trace(command, result)
    if target is None:
        return
    _write_event({"ts": _now(), "event": "trace_start", "trace_path": TRACE_PATH, "pid": target.GetProcess().GetProcessID(), "target": str(target.GetExecutable())})

    def meta_builder(bp, spec):
        BREAKPOINT_META[bp.GetID()] = {"name": spec[0], "selector": spec[1], "registers": spec[2]}

    _set_breakpoints(TRACE_SPECS, "screensharing_tools._trace_callback", result, meta_builder)
    result.AppendMessage(f"trace_file={TRACE_PATH}")


def _bypass_callback(frame, bp_loc, internal_dict):
    meta = BREAKPOINT_META.get(bp_loc.GetBreakpoint().GetID(), {})
    event = {
        "ts": _now(),
        "event": meta.get("name"),
        "selector": meta.get("selector"),
        "function": _frame_name(frame),
        "thread_id": frame.GetThread().GetThreadID(),
        "backtrace": _backtrace(frame.GetThread()),
    }
    for reg_name in meta.get("registers", []):
        event.setdefault("registers", {})[reg_name] = _reg_value(frame, reg_name)
    _write_event(event)
    return False


def _set_bypass(debugger, command, result, internal_dict):
    target = _prepare_trace(command, result)
    if target is None:
        return
    _write_event({"ts": _now(), "event": "bypass_start", "trace_path": TRACE_PATH, "pid": target.GetProcess().GetProcessID(), "target": str(target.GetExecutable())})

    def meta_builder(bp, spec):
        BREAKPOINT_META[bp.GetID()] = {"name": spec[0], "selector": spec[1], "registers": spec[2]}

    _set_breakpoints(BYPASS_SPECS, "screensharing_tools._bypass_callback", result, meta_builder)
    result.AppendMessage(f"trace_file={TRACE_PATH}")


def _make_value(frame, expression):
    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC_plus_plus)
    options.SetIgnoreBreakpoints(True)
    options.SetTrapExceptions(False)
    options.SetTimeoutInMicroSeconds(250000)
    value = frame.EvaluateExpression(expression, options)
    if not value or not value.IsValid() or value.GetError().Fail():
        return None
    return value


def _force_callback(frame, bp_loc, internal_dict):
    meta = BREAKPOINT_META.get(bp_loc.GetBreakpoint().GetID(), {})
    value = _make_value(frame, meta["return_expr"])
    ok = False
    error_text = None
    if value is not None:
        error = frame.GetThread().ReturnFromFrame(frame, value)
        ok = error is not None and error.Success()
        if error is not None and error.Fail():
            error_text = error.GetCString()
    event = {
        "ts": _now(),
        "event": "forced_return",
        "name": meta.get("name"),
        "selector": meta.get("selector"),
        "function": _frame_name(frame),
        "thread_id": frame.GetThread().GetThreadID(),
        "return_expr": meta.get("return_expr"),
        "forced": ok,
        "error": error_text,
        "backtrace": _backtrace(frame.GetThread()),
    }
    _write_event(event)
    return False


def _set_force(debugger, command, result, internal_dict):
    target = _prepare_trace(command, result)
    if target is None:
        return
    _write_event({"ts": _now(), "event": "force_start", "trace_path": TRACE_PATH, "pid": target.GetProcess().GetProcessID(), "target": str(target.GetExecutable())})

    def meta_builder(bp, spec):
        BREAKPOINT_META[bp.GetID()] = {"name": spec[0], "selector": spec[1], "return_expr": spec[2]}

    _set_breakpoints(FORCE_SPECS, "screensharing_tools._force_callback", result, meta_builder)
    result.AppendMessage(f"trace_file={TRACE_PATH}")


def _read_bytes(process, addr, size):
    error = lldb.SBError()
    data = process.ReadMemory(addr, size, error)
    if error.Success():
        return data, None
    return None, error.GetCString()


def _write_bytes(process, addr, data):
    error = lldb.SBError()
    written = process.WriteMemory(addr, data, error)
    if error.Success() and written == len(data):
        return True, None
    msg = error.GetCString() if error.GetCString() else f"short write {written}/{len(data)}"
    return False, msg


def _patch_callback(frame, bp_loc, internal_dict):
    meta = BREAKPOINT_META.get(bp_loc.GetBreakpoint().GetID(), {})
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    load_addr = frame.GetPCAddress().GetLoadAddress(target)
    selector = meta.get("selector")
    event = {
        "ts": _now(),
        "event": "patch_attempt",
        "name": meta.get("name"),
        "selector": selector,
        "function": _frame_name(frame),
        "pc": hex(load_addr) if load_addr != lldb.LLDB_INVALID_ADDRESS else None,
        "thread_id": thread.GetThreadID(),
        "backtrace": _backtrace(thread),
    }
    if selector in PATCHED_SELECTORS:
        event["patched"] = True
        event["already_patched"] = True
        _write_event(event)
        return False
    original, read_error = _read_bytes(process, load_addr, len(PATCH_BYTES))
    if original is None:
        event["patched"] = False
        event["error"] = read_error
        _write_event(event)
        return False
    ok, write_error = _write_bytes(process, load_addr, PATCH_BYTES)
    event["original_bytes"] = original.hex()
    event["patched_bytes"] = PATCH_BYTES.hex()
    event["patched"] = ok
    if not ok:
        event["error"] = write_error
    else:
        PATCHED_SELECTORS.add(selector)
    _write_event(event)
    return False


def _set_patch(debugger, command, result, internal_dict):
    target = _prepare_trace(command, result)
    if target is None:
        return
    _write_event({"ts": _now(), "event": "patch_start", "trace_path": TRACE_PATH, "pid": target.GetProcess().GetProcessID(), "target": str(target.GetExecutable()), "patch_bytes": PATCH_BYTES.hex()})

    def meta_builder(bp, spec):
        bp.SetAutoContinue(True)
        BREAKPOINT_META[bp.GetID()] = {"name": spec[0], "selector": spec[1]}

    _set_breakpoints(PATCH_SPECS, "screensharing_tools._patch_callback", result, meta_builder)
    result.AppendMessage(f"trace_file={TRACE_PATH}")


def _find_screensharingd_module(target):
    for module in target.module_iter():
        spec = module.GetFileSpec()
        if spec.GetFilename() == "screensharingd":
            return module
    return None


def _autodisable_on_hit(frame, bp_loc, internal_dict):
    bp = bp_loc.GetBreakpoint()
    if bp and bp.IsValid():
        bp.SetEnabled(False)
        name = bp.GetNameAtIndex(0) if bp.GetNumNames() else "unknown"
        print("auto-disabled {} (bp {})".format(name, bp.GetID()))
    return True


def _set_rebased_breakpoints(result, items, auto_disable_names):
    target = lldb.debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        result.SetError("no valid target")
        return
    module = _find_screensharingd_module(target)
    if module is None:
        result.SetError("screensharingd module not loaded")
        return
    header_addr = module.GetObjectFileHeaderAddress()
    load_base = header_addr.GetLoadAddress(target)
    file_base = header_addr.GetFileAddress()
    slide = load_base - file_base
    created = []
    for name, static_addr in items:
        runtime_addr = static_addr + slide
        cmd_result = lldb.SBCommandReturnObject()
        lldb.debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H -a {}".format(hex(runtime_addr)), cmd_result)
        if not cmd_result.Succeeded():
            result.AppendWarning("failed to set hardware breakpoint for {} at {}: {}".format(name, hex(runtime_addr), cmd_result.GetError().strip()))
            continue
        bp = target.GetBreakpointAtIndex(target.GetNumBreakpoints() - 1)
        if bp and bp.IsValid():
            bp.SetOneShot(True)
            bp.SetThreadID(0)
            bp.AddName(name)
            if name in auto_disable_names:
                bp.SetScriptCallbackFunction("screensharing_tools._autodisable_on_hit")
            created.append((name, static_addr, runtime_addr, bp.GetID()))
    result.AppendMessage("screensharingd slide={} file_base={} load_base={}".format(hex(slide), hex(file_base), hex(load_base)))
    for name, static_addr, runtime_addr, bp_id in created:
        result.AppendMessage("[{}] bp {} static={} runtime={}".format(name, bp_id, hex(static_addr), hex(runtime_addr)))


def _set_auth33_auto(debugger, command, result, internal_dict):
    _set_rebased_breakpoints(result, AUTH33_STATIC_ADDRESSES, AUTH33_AUTO_DISABLE)


def _set_hp_auto(debugger, command, result, internal_dict):
    _set_rebased_breakpoints(result, HP_STATIC_ADDRESSES, HP_AUTO_DISABLE)


def _set_srpkey_auto(debugger, command, result, internal_dict):
    _set_rebased_breakpoints(result, SRPKEY_STATIC_ADDRESSES, set())


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f screensharing_tools._set_trace ssviewer-trace")
    debugger.HandleCommand("command script add -f screensharing_tools._set_bypass ssviewer-bypass")
    debugger.HandleCommand("command script add -f screensharing_tools._set_force ssviewer-force-hp")
    debugger.HandleCommand("command script add -f screensharing_tools._set_patch ssviewer-patch-hp")
    debugger.HandleCommand("command script add -f screensharing_tools._set_auth33_auto ssauth33-auto")
    debugger.HandleCommand("command script add -f screensharing_tools._set_hp_auto sshp-auto")
    debugger.HandleCommand("command script add -f screensharing_tools._set_srpkey_auto sssrpkey-auto")
