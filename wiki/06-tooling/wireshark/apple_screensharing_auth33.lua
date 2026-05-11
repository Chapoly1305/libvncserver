local apple_ss = Proto("apple_ss_auth33", "Apple Screen Sharing Auth33")

local vnc_dissector = Dissector.get("vnc")
local f_tcp_stream = Field.new("tcp.stream")

local authtype_vals = {
    [0] = "key-request",
    [1] = "plain-auth",
    [2] = "srp-auth",
}

local state_by_stream = {}

apple_ss.prefs.session_key_hex = Pref.string(
    "session_key_hex",
    "",
    "AES-128 session key in hex for experimental post-auth decryption"
)
apple_ss.prefs.client_mode = Pref.string(
    "client_mode",
    "auto",
    "Client->Server decrypt mode: auto, none, aes-128-ecb, aes-128-cbc-zero-iv"
)
apple_ss.prefs.server_mode = Pref.string(
    "server_mode",
    "auto",
    "Server->Client decrypt mode: auto, none, aes-128-ecb, aes-128-cbc-zero-iv"
)
apple_ss.prefs.client_offset = Pref.uint("client_offset", 0, "Bytes to skip before client->server decrypt")
apple_ss.prefs.server_offset = Pref.uint("server_offset", 0, "Bytes to skip before server->client decrypt")
apple_ss.prefs.max_preview = Pref.uint("max_preview", 64, "Max plaintext preview bytes to show")

local pf_phase = ProtoField.string("apple_ss_auth33.phase", "Phase")
local pf_stream = ProtoField.uint32("apple_ss_auth33.stream", "TCP Stream", base.DEC)
local pf_security_count = ProtoField.uint8("apple_ss_auth33.security.count", "Security Type Count", base.DEC)
local pf_security_type = ProtoField.uint8("apple_ss_auth33.security.type", "Security Type", base.DEC)
local pf_security_selected = ProtoField.uint8("apple_ss_auth33.security.selected", "Selected Security Type", base.DEC)
local pf_rsa1_len = ProtoField.uint32("apple_ss_auth33.rsa1.len", "RSA1 Length Prefix", base.DEC)
local pf_rsa1_version = ProtoField.uint16("apple_ss_auth33.rsa1.version", "RSA1 Packet Version", base.HEX)
local pf_rsa1_magic = ProtoField.string("apple_ss_auth33.rsa1.magic", "RSA1 Magic")
local pf_rsa1_authtype = ProtoField.uint16("apple_ss_auth33.rsa1.authtype", "RSA1 Auth Type", base.DEC, authtype_vals)
local pf_rsa1_aux = ProtoField.uint16("apple_ss_auth33.rsa1.aux", "RSA1 Aux", base.DEC)
local pf_rsa1_body_len = ProtoField.uint32("apple_ss_auth33.rsa1.body_len", "RSA1 Body Length", base.DEC)
local pf_rsa1_body_nz = ProtoField.uint32("apple_ss_auth33.rsa1.body_non_zero", "RSA1 Non-Zero Body Bytes", base.DEC)
local pf_srp_total_len = ProtoField.uint32("apple_ss_auth33.srp.total_len", "SRP Total Length", base.DEC)
local pf_srp_step = ProtoField.uint32("apple_ss_auth33.srp.step", "SRP Step", base.DEC)
local pf_srp_x = ProtoField.uint16("apple_ss_auth33.srp.x", "SRP X", base.DEC)
local pf_srp_inner_len = ProtoField.uint32("apple_ss_auth33.srp.inner_len", "SRP Inner Length", base.DEC)
local pf_srp_flags = ProtoField.uint8("apple_ss_auth33.srp.flags", "SRP Flags", base.HEX)
local pf_srp_n_len = ProtoField.uint16("apple_ss_auth33.srp.n_len", "SRP N Length", base.DEC)
local pf_srp_g = ProtoField.bytes("apple_ss_auth33.srp.g", "SRP g")
local pf_srp_salt = ProtoField.bytes("apple_ss_auth33.srp.salt", "SRP Salt")
local pf_srp_b_len = ProtoField.uint16("apple_ss_auth33.srp.b_len", "SRP B Length", base.DEC)
local pf_srp_kdf_iters = ProtoField.uint64("apple_ss_auth33.srp.kdf_iters", "SRP KDF Iterations", base.DEC)
local pf_srp_options = ProtoField.string("apple_ss_auth33.srp.options", "SRP Options")
local pf_client_init = ProtoField.uint8("apple_ss_auth33.client_init.raw", "ClientInit", base.HEX)
local pf_client_init_shared = ProtoField.bool("apple_ss_auth33.client_init.shared", "ClientInit Shared Desktop", 8, nil, 0x01)
local pf_client_init_bit6 = ProtoField.bool("apple_ss_auth33.client_init.bit6", "ClientInit Bit 6", 8, nil, 0x40)
local pf_client_init_bit7 = ProtoField.bool("apple_ss_auth33.client_init.bit7", "ClientInit Bit 7", 8, nil, 0x80)
local pf_server_width = ProtoField.uint16("apple_ss_auth33.server_init.width", "Framebuffer Width", base.DEC)
local pf_server_height = ProtoField.uint16("apple_ss_auth33.server_init.height", "Framebuffer Height", base.DEC)
local pf_server_name_len = ProtoField.uint32("apple_ss_auth33.server_init.name_len", "Server Name Length", base.DEC)
local pf_server_name = ProtoField.string("apple_ss_auth33.server_init.name", "Server Name")
local pf_security_result = ProtoField.uint32("apple_ss_auth33.security_result", "Security Result", base.DEC)
local pf_post_msg_id = ProtoField.uint8("apple_ss_auth33.post.msg_id", "Post-Auth Message ID", base.HEX)
local pf_post_msg_name = ProtoField.string("apple_ss_auth33.post.msg_name", "Post-Auth Message")
local pf_post_msg_len = ProtoField.uint32("apple_ss_auth33.post.msg_len", "Post-Auth Length", base.DEC)
local pf_post_name_len = ProtoField.uint32("apple_ss_auth33.post.name_len", "Post-Auth Name Length", base.DEC)
local pf_post_clip_len = ProtoField.uint32("apple_ss_auth33.post.clip_len", "Clipboard Text Length", base.DEC)
local pf_post_display_name = ProtoField.string("apple_ss_auth33.post.display_name", "Display Name")
local pf_post_rfb_msg = ProtoField.uint8("apple_ss_auth33.post.rfb_msg", "RFB Message Type", base.HEX)
local pf_post_rect_count = ProtoField.uint16("apple_ss_auth33.post.rect_count", "Rectangle Count", base.DEC)
local pf_post_rect_x = ProtoField.uint16("apple_ss_auth33.post.rect_x", "Rectangle X", base.DEC)
local pf_post_rect_y = ProtoField.uint16("apple_ss_auth33.post.rect_y", "Rectangle Y", base.DEC)
local pf_post_rect_w = ProtoField.uint16("apple_ss_auth33.post.rect_w", "Rectangle Width", base.DEC)
local pf_post_rect_h = ProtoField.uint16("apple_ss_auth33.post.rect_h", "Rectangle Height", base.DEC)
local pf_post_rect_encoding = ProtoField.uint32("apple_ss_auth33.post.rect_encoding", "Rectangle Encoding", base.HEX)
local pf_post_rect_payload_len = ProtoField.uint16("apple_ss_auth33.post.rect_payload_len", "Rectangle Payload Length", base.DEC)
local pf_post_rect_item_count = ProtoField.uint16("apple_ss_auth33.post.rect_item_count", "Rectangle Item Count", base.DEC)
local pf_post_rect_version = ProtoField.uint16("apple_ss_auth33.post.rect_version", "Rectangle Version", base.DEC)
local pf_post_rect_flags = ProtoField.uint32("apple_ss_auth33.post.rect_flags", "Rectangle Flags", base.HEX)
local pf_post_rect_value_count = ProtoField.uint16("apple_ss_auth33.post.rect_value_count", "Rectangle Value Count", base.DEC)
local pf_post_rect_values = ProtoField.string("apple_ss_auth33.post.rect_values", "Rectangle Values")
local pf_post_rect_string1_len = ProtoField.uint16("apple_ss_auth33.post.rect_string1_len", "Rectangle String 1 Length", base.DEC)
local pf_post_rect_string2_len = ProtoField.uint16("apple_ss_auth33.post.rect_string2_len", "Rectangle String 2 Length", base.DEC)
local pf_post_rect_string3_len = ProtoField.uint16("apple_ss_auth33.post.rect_string3_len", "Rectangle String 3 Length", base.DEC)
local pf_post_rect_housing_color = ProtoField.uint32("apple_ss_auth33.post.rect_housing_color", "Rectangle Housing Color", base.DEC)
local pf_post_rect_string1 = ProtoField.string("apple_ss_auth33.post.rect_string1", "Rectangle String 1")
local pf_post_rect_string2 = ProtoField.string("apple_ss_auth33.post.rect_string2", "Rectangle String 2")
local pf_post_rect_string3 = ProtoField.string("apple_ss_auth33.post.rect_string3", "Rectangle String 3")
local pf_post_rect_note = ProtoField.string("apple_ss_auth33.post.rect_note", "Rectangle Note")
local pf_post_client_cmd = ProtoField.uint16("apple_ss_auth33.post.client_cmd", "Client Command", base.DEC)
local pf_post_client_target = ProtoField.uint32("apple_ss_auth33.post.client_target", "Client Target / Selected Screen", base.HEX)
local pf_post_encinfo_counter = ProtoField.uint32("apple_ss_auth33.post.encinfo.counter", "EncryptionInfo Counter", base.DEC)
local pf_post_encinfo_block1 = ProtoField.bytes("apple_ss_auth33.post.encinfo.block1", "EncryptionInfo Block 1")
local pf_post_encinfo_block2 = ProtoField.bytes("apple_ss_auth33.post.encinfo.block2", "EncryptionInfo Block 2")
local pf_post_wrap_key = ProtoField.string("apple_ss_auth33.post.wrap_key", "Active Wrap Key")
local pf_post_next_key = ProtoField.string("apple_ss_auth33.post.next_key", "Derived Next Key")
local pf_post_next_iv = ProtoField.string("apple_ss_auth33.post.next_iv", "Derived Next IV")
local pf_post_cbc_key = ProtoField.string("apple_ss_auth33.post.cbc_key", "Active CBC Key")
local pf_post_cbc_server_iv = ProtoField.string("apple_ss_auth33.post.cbc_server_iv", "Server->Client CBC IV")
local pf_post_cbc_client_iv = ProtoField.string("apple_ss_auth33.post.cbc_client_iv", "Client->Server CBC IV")
local pf_post_record_index = ProtoField.uint32("apple_ss_auth33.post.record_index", "Record Index", base.DEC)
local pf_post_record_seq = ProtoField.uint32("apple_ss_auth33.post.record_seq", "Inferred Record Sequence", base.DEC)
local pf_post_record_cipher_len = ProtoField.uint32("apple_ss_auth33.post.record_cipher_len", "Ciphertext Length", base.DEC)
local pf_post_record_body_len = ProtoField.uint32("apple_ss_auth33.post.record_body_len", "Plaintext Body Length", base.DEC)
local pf_post_record_filler_len = ProtoField.uint32("apple_ss_auth33.post.record_filler_len", "Filler Length", base.DEC)
local pf_post_record_filler_hex = ProtoField.string("apple_ss_auth33.post.record_filler_hex", "Filler Bytes")
local pf_post_record_sha1 = ProtoField.string("apple_ss_auth33.post.record_sha1", "Trailing SHA1")
local pf_post_mode = ProtoField.string("apple_ss_auth33.post.mode", "Post-Auth Mode")
local pf_post_offset = ProtoField.uint32("apple_ss_auth33.post.offset", "Post-Auth Offset", base.DEC)
local pf_post_payload_len = ProtoField.uint32("apple_ss_auth33.post.payload_len", "Post-Auth Payload Length", base.DEC)
local pf_post_plain_len = ProtoField.uint32("apple_ss_auth33.post.plain_len", "Decrypted Plaintext Length", base.DEC)
local pf_post_plain_hex = ProtoField.string("apple_ss_auth33.post.plain_hex", "Decrypted Plaintext (Hex)")
local pf_post_plain_ascii = ProtoField.string("apple_ss_auth33.post.plain_ascii", "Decrypted Plaintext (ASCII)")
local pf_post_guess = ProtoField.string("apple_ss_auth33.post.guess", "Guessed Meaning")

apple_ss.fields = {
    pf_phase,
    pf_stream,
    pf_security_count,
    pf_security_type,
    pf_security_selected,
    pf_rsa1_len,
    pf_rsa1_version,
    pf_rsa1_magic,
    pf_rsa1_authtype,
    pf_rsa1_aux,
    pf_rsa1_body_len,
    pf_rsa1_body_nz,
    pf_srp_total_len,
    pf_srp_step,
    pf_srp_x,
    pf_srp_inner_len,
    pf_srp_flags,
    pf_srp_n_len,
    pf_srp_g,
    pf_srp_salt,
    pf_srp_b_len,
    pf_srp_kdf_iters,
    pf_srp_options,
    pf_client_init,
    pf_client_init_shared,
    pf_client_init_bit6,
    pf_client_init_bit7,
    pf_server_width,
    pf_server_height,
    pf_server_name_len,
    pf_server_name,
    pf_security_result,
    pf_post_msg_id,
    pf_post_msg_name,
    pf_post_msg_len,
    pf_post_name_len,
    pf_post_clip_len,
    pf_post_display_name,
    pf_post_rfb_msg,
    pf_post_rect_count,
    pf_post_rect_x,
    pf_post_rect_y,
    pf_post_rect_w,
    pf_post_rect_h,
    pf_post_rect_encoding,
    pf_post_rect_payload_len,
    pf_post_rect_item_count,
    pf_post_rect_version,
    pf_post_rect_flags,
    pf_post_rect_value_count,
    pf_post_rect_values,
    pf_post_rect_string1_len,
    pf_post_rect_string2_len,
    pf_post_rect_string3_len,
    pf_post_rect_housing_color,
    pf_post_rect_string1,
    pf_post_rect_string2,
    pf_post_rect_string3,
    pf_post_rect_note,
    pf_post_client_cmd,
    pf_post_client_target,
    pf_post_encinfo_counter,
    pf_post_encinfo_block1,
    pf_post_encinfo_block2,
    pf_post_wrap_key,
    pf_post_next_key,
    pf_post_next_iv,
    pf_post_cbc_key,
    pf_post_cbc_server_iv,
    pf_post_cbc_client_iv,
    pf_post_record_index,
    pf_post_record_seq,
    pf_post_record_cipher_len,
    pf_post_record_body_len,
    pf_post_record_filler_len,
    pf_post_record_filler_hex,
    pf_post_record_sha1,
    pf_post_mode,
    pf_post_offset,
    pf_post_payload_len,
    pf_post_plain_len,
    pf_post_plain_hex,
    pf_post_plain_ascii,
    pf_post_guess,
}

local function reset_state()
    state_by_stream = {}
end

local function get_stream_state(stream_id)
    local st = state_by_stream[stream_id]
    if st == nil then
        st = {
            phase = "unknown",
            auth_complete = false,
            client_init_seen = false,
            server_init_seen = false,
            wrap_key_hex = nil,
            cbc_key_hex = nil,
            server_cbc_iv_hex = nil,
            client_cbc_iv_hex = nil,
            cbc_base_seq = nil,
            rekey_counter = 0,
            server_cbc_pending = "",
            client_cbc_pending = "",
            server_cbc_record_index = 0,
            client_cbc_record_index = 0,
        }
        state_by_stream[stream_id] = st
    end
    return st
end

local function be_u16(s, off)
    local a, b = s:byte(off + 1, off + 2)
    if a == nil or b == nil then
        return nil
    end
    return a * 256 + b
end

local function be_u32(s, off)
    local a, b, c, d = s:byte(off + 1, off + 4)
    if a == nil or d == nil then
        return nil
    end
    return (((a * 256 + b) * 256 + c) * 256 + d)
end

local function be_u64(s, off)
    local hi = be_u32(s, off)
    local lo = be_u32(s, off + 4)
    if hi == nil or lo == nil then
        return nil
    end
    return hi * 4294967296 + lo
end

local function hex_bytes(s, limit)
    if s == nil then
        return ""
    end
    local n = #s
    local out = {}
    local max_len = limit or n
    local use_len = math.min(n, max_len)
    for i = 1, use_len do
        out[#out + 1] = string.format("%02x", s:byte(i))
    end
    local joined = table.concat(out)
    if use_len < n then
        return joined .. string.format("... (%d bytes)", n)
    end
    return joined
end

local function ascii_preview(s, limit)
    if s == nil then
        return ""
    end
    local n = #s
    local out = {}
    local max_len = limit or n
    local use_len = math.min(n, max_len)
    for i = 1, use_len do
        local b = s:byte(i)
        if b >= 32 and b <= 126 then
            out[#out + 1] = string.char(b)
        else
            out[#out + 1] = "."
        end
    end
    local joined = table.concat(out)
    if use_len < n then
        return joined .. string.format("... (%d bytes)", n)
    end
    return joined
end

local function non_zero_count(s)
    local n = 0
    for i = 1, #s do
        if s:byte(i) ~= 0 then
            n = n + 1
        end
    end
    return n
end

local function parse_fmt_blob(fmt, blob)
    local values = {}
    local off = 0
    local i = 1
    while i <= #fmt do
        local ch = fmt:sub(i, i)
        if ch ~= "%" then
            i = i + 1
        else
            i = i + 1
            while i <= #fmt and fmt:sub(i, i) == "-" do
                i = i + 1
            end
            local t = fmt:sub(i, i)
            if t == "c" then
                values[#values + 1] = blob:sub(off + 1, off + 1)
                off = off + 1
            elseif t == "m" then
                local n = be_u16(blob, off)
                if n == nil then
                    return nil
                end
                values[#values + 1] = blob:sub(off + 3, off + 2 + n)
                off = off + 2 + n
            elseif t == "o" then
                local n = blob:byte(off + 1)
                if n == nil then
                    return nil
                end
                values[#values + 1] = blob:sub(off + 2, off + 1 + n)
                off = off + 1 + n
            elseif t == "s" then
                local n = be_u16(blob, off)
                if n == nil then
                    return nil
                end
                values[#values + 1] = blob:sub(off + 3, off + 2 + n)
                off = off + 2 + n
            elseif t == "u" then
                local n = be_u32(blob, off)
                if n == nil then
                    return nil
                end
                values[#values + 1] = n
                off = off + 4
            elseif t == "q" then
                local n = be_u64(blob, off)
                if n == nil then
                    return nil
                end
                values[#values + 1] = n
                off = off + 8
            else
                return nil
            end
            i = i + 1
        end
    end
    return values
end

local function blob_parse_ok(fmt, blob)
    local ok, vals = pcall(parse_fmt_blob, fmt, blob)
    if not ok or vals == nil then
        return false
    end
    return true
end

local function shell_quote(path)
    return "'" .. tostring(path):gsub("'", "'\\''") .. "'"
end

local function normalize_hex(s)
    if s == nil then
        return ""
    end
    return tostring(s):gsub("%s+", ""):lower()
end

local function valid_hex_n(s, n)
    return #s == n and s:match("^[0-9a-f]+$") ~= nil
end

local function ensure_stream_base_key(st)
    local pref_key = normalize_hex(apple_ss.prefs.session_key_hex)
    if not valid_hex_n(pref_key, 32) then
        return nil
    end
    if st.wrap_key_hex == nil then
        st.wrap_key_hex = pref_key
    end
    return st.wrap_key_hex
end

local function decrypt_with_openssl(mode_name, key_hex, iv_hex, payload)
    if payload == nil or #payload == 0 then
        return nil, "empty payload"
    end

    local in_name = os.tmpname()
    local out_name = os.tmpname()

    local inf = io.open(in_name, "wb")
    if inf == nil then
        return nil, "failed to open temp input"
    end
    inf:write(payload)
    inf:close()

    local cmd
    if mode_name == "aes-128-ecb" then
        cmd = string.format(
            "openssl enc -aes-128-ecb -d -nopad -nosalt -K %s -in %s -out %s 2>/dev/null",
            key_hex,
            shell_quote(in_name),
            shell_quote(out_name)
        )
    elseif mode_name == "aes-128-cbc-zero-iv" or mode_name == "aes-128-cbc" then
        cmd = string.format(
            "openssl enc -aes-128-cbc -d -nopad -nosalt -K %s -iv %s -in %s -out %s 2>/dev/null",
            key_hex,
            iv_hex or string.rep("0", 32),
            shell_quote(in_name),
            shell_quote(out_name)
        )
    else
        os.remove(in_name)
        return nil, "unsupported mode"
    end

    local rc = os.execute(cmd)
    local ok = (rc == true or rc == 0)
    if not ok then
        os.remove(in_name)
        os.remove(out_name)
        return nil, "openssl failed"
    end

    local outf = io.open(out_name, "rb")
    if outf == nil then
        os.remove(in_name)
        os.remove(out_name)
        return nil, "failed to open temp output"
    end
    local plain = outf:read("*all")
    outf:close()
    os.remove(in_name)
    os.remove(out_name)
    return plain, nil
end

local function decrypt_candidate(key_hex, mode_name, offset, payload, iv_hex)
    if offset >= #payload then
        return nil, "offset past end"
    end
    local enc = payload:sub(offset + 1)
    local usable = #enc - (#enc % 16)
    if usable <= 0 then
        return nil, "no block-aligned ciphertext"
    end
    local dec, err = decrypt_with_openssl(mode_name, key_hex, iv_hex or string.rep("0", 32), enc:sub(1, usable))
    if dec == nil then
        return nil, err
    end
    return dec, nil
end

local function guess_client_message_type(b)
    local m = {
        [0] = "SetPixelFormat",
        [2] = "SetEncodings",
        [3] = "FramebufferUpdateRequest",
        [4] = "KeyEvent",
        [5] = "PointerEvent",
        [6] = "ClientCutText",
        [9] = "AutoFrameBufferUpdate",
        [8] = "AppleScaleFactorMessage?",
        [10] = "SetModeMessage",
        [13] = "SetDisplayMessage",
        [18] = "SetEncryptionMessage",
        [21] = "AutoPasteboardCommand",
        [16] = "AppleKeyboardSourceMessage?",
        [29] = "Apple/unknown extension",
        [33] = "Apple/unknown extension",
    }
    return m[b] or "unknown"
end

local function guess_server_message_type(b)
    local m = {
        [0] = "FramebufferUpdate",
        [1] = "SetColorMapEntries",
        [2] = "Bell",
        [3] = "ServerCutText",
        [150] = "Apple/unknown extension",
    }
    return m[b] or "unknown"
end

local function post_auth_message_name(msg_id)
    local m = {
        [0x12] = "SetEncryptionMessage",
        [0x1d] = "SetDisplayConfiguration",
        [0x21] = "ViewerInfo",
        [0x44f] = "EncodeEncryptionInfo",
    }
    return m[msg_id] or "unknown"
end

local function rectangle_encoding_name(enc)
    local m = {
        [0x00000006] = "Zlib",
        [0x450] = "CursorImage",
        [0x44f] = "EncodeEncryptionInfo",
        [0x451] = "AppleDisplayLayout",
        [0x453] = "VendorKeysymEncoding",
        [0x455] = "KeyboardInputSource",
        [0x456] = "DeviceInfo",
        [0x3f2] = "RFBMediaStreamMessage1",
        [0xffffff21] = "DesktopSize",
    }
    return m[enc] or "unknown"
end

local function add_candidate_tree(tree, mode_name, offset, payload, key_hex, direction, iv_hex)
    local subtree = tree:add(apple_ss, string.format("Experimental %s decrypt", mode_name))
    subtree:add(pf_post_mode, mode_name)
    subtree:add(pf_post_offset, offset)
    subtree:add(pf_post_payload_len, #payload)

    local plain, err = decrypt_candidate(key_hex, mode_name, offset, payload, iv_hex)
    if plain == nil then
        subtree:add_expert_info(PI_UNDECODED, PI_NOTE, "Decrypt failed: " .. tostring(err))
        return
    end

    subtree:add(pf_post_plain_len, #plain)
    subtree:add(pf_post_plain_hex, hex_bytes(plain, apple_ss.prefs.max_preview))
    subtree:add(pf_post_plain_ascii, ascii_preview(plain, apple_ss.prefs.max_preview))

    local first = plain:byte(1)
    if first ~= nil then
        local guess
        if direction == "client" then
            guess = guess_client_message_type(first)
        else
            guess = guess_server_message_type(first)
        end
        subtree:add(pf_post_guess, string.format("first_byte=0x%02x %s", first, guess))
    end
end

local function classify_rfb_payload(body, direction)
    if #body == 0 then
        return "empty"
    end
    local first = body:byte(1)
    if direction == "client" then
        return guess_client_message_type(first)
    end
    return guess_server_message_type(first)
end

local function parse_len_prefixed_string(body, off)
    local n = be_u16(body, off)
    if n == nil then
        return nil, nil
    end
    local start = off + 2
    local stop = start + n
    if stop > #body then
        return nil, nil
    end
    return body:sub(start + 1, stop), stop
end

local function parse_framebuffer_update_rect_details(record_tree, body, enc)
    if enc == 0x450 then
        local cache_id = be_u32(body, 16)
        local zlib_len = be_u32(body, 20)
        if zlib_len ~= nil then
            record_tree:add(pf_post_rect_payload_len, zlib_len)
        end
        if cache_id ~= nil and zlib_len ~= nil then
            record_tree:add(
                pf_post_rect_note,
                string.format(
                    "cursor-image schema: cache_id=%u zlib_len=%u%s",
                    cache_id,
                    zlib_len,
                    zlib_len == 0 and " cached-image reuse" or " zlib payload follows"
                )
            )
        end
        return
    end

    if enc == 0x00000006 then
        local zlib_len = be_u32(body, 16)
        if zlib_len ~= nil then
            record_tree:add(pf_post_rect_payload_len, zlib_len)
            record_tree:add(
                pf_post_rect_note,
                string.format("standard zlib rectangle: compressed_len=%u", zlib_len)
            )
        end
        return
    end

    local payload_len = be_u16(body, 16)
    local item_count = be_u16(body, 18)
    if payload_len ~= nil then
        record_tree:add(pf_post_rect_payload_len, payload_len)
    end
    if item_count ~= nil then
        record_tree:add(pf_post_rect_item_count, item_count)
        record_tree:add(pf_post_rect_version, item_count)
    end

    if enc == 0x3f2 then
        local version = be_u16(body, 18)
        local base_udp_port = be_u16(body, 20)
        local stream_count = be_u16(body, 22)
        local next_udp_port = be_u16(body, 24)
        if version ~= nil then
            record_tree:add(pf_post_rect_version, version)
        end
        record_tree:add(
            pf_post_rect_note,
            string.format(
                "media-stream-init schema: version=%u base_udp_port=%u stream_count=%u next_udp_port=%u remaining fields open",
                version or 0,
                base_udp_port or 0,
                stream_count or 0,
                next_udp_port or 0
            )
        )
    elseif enc == 0x451 then
        local width1 = be_u16(body, 20)
        local height1 = be_u16(body, 22)
        local width2 = be_u16(body, 24)
        local height2 = be_u16(body, 26)
        local selected_screen = be_u32(body, 28)
        local display_flags = be_u32(body, 32)
        local scale_factor_is_one = body:sub(37, 44) == "\x3f\xf0\x00\x00\x00\x00\x00\x00"
        if width1 ~= nil and height1 ~= nil and width2 ~= nil and height2 ~= nil then
            record_tree:add(
                pf_post_rect_note,
                string.format(
                    "candidate schema: version=%d scaled=%dx%d ui=%dx%d selected=0x%08x flags=0x%08x scale_factor=%s pixel_format_tail=32/32 true-color",
                    item_count or 0,
                    width1,
                    height1,
                    width2,
                    height2,
                    selected_screen or 0,
                    display_flags or 0,
                    scale_factor_is_one and "1.0" or "open"
                )
            )
        end
    elseif enc == 0x453 then
        local value_count = be_u16(body, 20)
        if value_count ~= nil then
            record_tree:add(pf_post_rect_value_count, value_count)
            local values = {}
            local off = 22
            for _ = 1, value_count do
                local v = be_u32(body, off)
                if v == nil then
                    break
                end
                values[#values + 1] = string.format("0x%08x", v)
                off = off + 4
            end
            if #values > 0 then
                record_tree:add(pf_post_rect_values, table.concat(values, ", "))
                record_tree:add(pf_post_rect_note, "vendor-keysym value list")
            end
        end
    elseif enc == 0x455 then
        local flags = be_u32(body, 20)
        if flags ~= nil then
            record_tree:add(pf_post_rect_flags, flags)
        end
        local s1_len = be_u16(body, 24)
        if s1_len ~= nil then
            record_tree:add(pf_post_rect_string1_len, s1_len)
        end
        local s1 = parse_len_prefixed_string(body, 24)
        if s1 ~= nil then
            record_tree:add(pf_post_rect_string1, s1)
        end
        record_tree:add(pf_post_rect_note, "keyboard-input-source schema: version, flags, string_len, source_id")
    elseif enc == 0x456 then
        local block_count = be_u32(body, 20)
        local flags = be_u32(body, 24)
        local s1_len = be_u16(body, 28)
        local s2_len = be_u16(body, 30)
        local s3_len = be_u16(body, 32)
        if flags ~= nil then
            record_tree:add(pf_post_rect_flags, flags)
        end
        if s1_len ~= nil then
            record_tree:add(pf_post_rect_string1_len, s1_len)
        end
        if s2_len ~= nil then
            record_tree:add(pf_post_rect_string2_len, s2_len)
        end
        if s3_len ~= nil then
            record_tree:add(pf_post_rect_string3_len, s3_len)
        end
        local cursor = 34
        local s1
        if s1_len ~= nil and cursor + s1_len <= #body then
            s1 = body:sub(cursor + 1, cursor + s1_len)
            if s1:sub(-1) == "\x00" then
                s1 = s1:sub(1, -2)
            end
            record_tree:add(pf_post_rect_string1, s1)
            cursor = cursor + s1_len
        end
        if s2_len ~= nil and cursor + s2_len <= #body then
            local s2 = body:sub(cursor + 1, cursor + s2_len)
            if s2:sub(-1) == "\x00" then
                s2 = s2:sub(1, -2)
            end
            record_tree:add(pf_post_rect_string2, s2)
            cursor = cursor + s2_len
        end
        if s3_len ~= nil and cursor + s3_len <= #body then
            local s3 = body:sub(cursor + 1, cursor + s3_len)
            if s3:sub(-1) == "\x00" then
                s3 = s3:sub(1, -2)
            end
            record_tree:add(pf_post_rect_string3, s3)
            cursor = cursor + s3_len
        end
        local housing_color = be_u32(body, cursor)
        if housing_color ~= nil then
            record_tree:add(pf_post_rect_housing_color, housing_color)
        end
        record_tree:add(
            pf_post_rect_note,
            string.format(
                "device-info schema: version=%d block_count=%u flags=0x%08x 3 string lengths + 3 strings + housing_color",
                item_count or 0,
                block_count or 0,
                flags or 0
            )
        )
    end
end

local function parse_framebuffer_update(record_tree, body)
    if #body < 16 then
        return
    end
    local enc = be_u32(body, 12) or 0
    record_tree:add(pf_post_rfb_msg, body:byte(1))
    record_tree:add(pf_post_rect_count, be_u16(body, 2) or 0)
    record_tree:add(pf_post_rect_x, be_u16(body, 4) or 0)
    record_tree:add(pf_post_rect_y, be_u16(body, 6) or 0)
    record_tree:add(pf_post_rect_w, be_u16(body, 8) or 0)
    record_tree:add(pf_post_rect_h, be_u16(body, 10) or 0)
    record_tree:add(pf_post_rect_encoding, enc)
    record_tree:add(pf_post_guess, string.format("rect_encoding=0x%04x %s", enc, rectangle_encoding_name(enc)))
    parse_framebuffer_update_rect_details(record_tree, body, enc)
end

local function parse_set_pixel_format(record_tree, body)
    if #body < 20 then
        return
    end
    record_tree:add(pf_post_guess, "SetPixelFormat")
end

local function parse_set_encodings(record_tree, body)
    if #body < 4 then
        return
    end
    record_tree:add(pf_post_guess, "SetEncodings")
end

local function parse_framebuffer_update_request(record_tree, body)
    if #body < 10 then
        return
    end
    record_tree:add(pf_post_guess, string.format("FramebufferUpdateRequest incremental=%u", body:byte(2) or 0))
    record_tree:add(pf_post_rect_x, be_u16(body, 2) or 0)
    record_tree:add(pf_post_rect_y, be_u16(body, 4) or 0)
    record_tree:add(pf_post_rect_w, be_u16(body, 6) or 0)
    record_tree:add(pf_post_rect_h, be_u16(body, 8) or 0)
end

local function parse_auto_framebuffer_update(record_tree, body)
    if #body < 16 then
        return
    end
    local version = be_u16(body, 2)
    local target = be_u32(body, 4)
    local x = be_u16(body, 8)
    local y = be_u16(body, 10)
    local w = be_u16(body, 12)
    local h = be_u16(body, 14)
    if version ~= nil then
        record_tree:add(pf_post_client_cmd, version)
    end
    if target ~= nil then
        record_tree:add(pf_post_client_target, target)
    end
    record_tree:add(pf_post_rect_x, x or 0)
    record_tree:add(pf_post_rect_y, y or 0)
    record_tree:add(pf_post_rect_w, w or 0)
    record_tree:add(pf_post_rect_h, h or 0)
    record_tree:add(
        pf_post_rect_note,
        string.format(
            "HandleAutoFrameBufferUpdateMessage: version=%u target=0x%08x region=(%u,%u %ux%u) target=0xffffffff means no explicit selected screen",
            version or 0,
            target or 0,
            x or 0,
            y or 0,
            w or 0,
            h or 0
        )
    )
end

local function be_double(body, off)
    local hex = hex_bytes(body:sub(off + 1, off + 8))
    if #hex ~= 16 then
        return nil
    end
    local cmd = string.format("python3 - <<'PY'\nimport struct\nprint(repr(struct.unpack(\">d\", bytes.fromhex(\"%s\"))[0]))\nPY", hex)
    local f = io.popen(cmd, "r")
    if f == nil then
        return nil
    end
    local out = f:read("*a")
    f:close()
    if out == nil then
        return nil
    end
    return tonumber((out:gsub("%s+", "")))
end

local function parse_scale_factor_message(record_tree, body)
    if #body < 10 then
        return
    end
    local flags = be_u16(body, 2) or 0
    local scale = be_double(body, 2)
    record_tree:add(
        pf_post_rect_note,
        string.format(
            "strong-inference: client 0x08 carries a BE double-like value after a 2-byte flags field; native sample decodes to scale=%s flags=0x%04x, matches viewer scaleFactor symbols, and is followed by 0x03/0x09 update regions whose 0x0c67x0x06fa dimensions align with a rounded scaled view of 3840x2160",
            scale ~= nil and tostring(scale) or "open",
            flags
        )
    )
end

local function parse_set_display_message(record_tree, body)
    if #body < 8 then
        return
    end
    local combine_all = body:byte(2) or 0
    local target = be_u32(body, 4)
    if target ~= nil then
        record_tree:add(pf_post_client_target, target)
    end
    record_tree:add(
        pf_post_rect_note,
        string.format(
            "HandleSetDisplayMessage: combine_all=%u target=0x%08x; confirmed native localhost body 0x0d01000000000000 means combine all displays / default aggregate",
            combine_all,
            target or 0
        )
    )
end

local function parse_set_mode_message(record_tree, body)
    if #body < 18 then
        return
    end
    record_tree:add(
        pf_post_rect_note,
        string.format(
            "open/strong-inference: client 0x10 is an 18-byte extension message with stable subtype 0x%02x and 16 opaque bytes; runtime timing clusters it with keyboard/keymap/input-source initialization rather than generic display mode control",
            body:byte(2) or 0
        )
    )
end

local function parse_auto_pasteboard_command(record_tree, body)
    if #body < 8 then
        return
    end
    local command = be_u16(body, 2)
    if command ~= nil then
        record_tree:add(pf_post_client_cmd, command)
    end
    record_tree:add(
        pf_post_rect_note,
        string.format(
            "HandleAutoPasteboardCommand: selector=%u (server accepts 1 or 2; exact UI meaning still open; native 24G419 post-rekey burst used selector=1)",
            command or 0
        )
    )
end

local function add_cbc_record_tree(post_tree, st, direction, offset, record_index, cipher_block, plain)
    local record_tree = post_tree:add(
        apple_ss,
        string.format("CBC record %d (%s)", record_index, direction)
    )
    local plain_len = be_u16(plain, 0)
    if plain_len == nil then
        record_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Missing inner plaintext length")
        return
    end

    local body_end = 2 + plain_len
    if #plain < body_end then
        record_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Inner plaintext shorter than declared length")
        return
    end

    local body = plain:sub(3, body_end)
    local tail_len = #plain - body_end
    local filler_len = tail_len >= 20 and (tail_len - 20) or 0
    local filler_hex = filler_len > 0 and hex_bytes(plain:sub(body_end + 1, #plain - 20)) or ""
    local sha1_hex = tail_len >= 20 and hex_bytes(plain:sub(#plain - 19)) or ""
    local seq = st.cbc_base_seq ~= nil and (st.cbc_base_seq + record_index - 1) or nil

    record_tree:add(pf_post_record_index, record_index)
    if seq ~= nil then
        record_tree:add(pf_post_record_seq, seq)
    end
    record_tree:add(pf_post_offset, offset)
    record_tree:add(pf_post_record_cipher_len, #cipher_block)
    record_tree:add(pf_post_plain_len, #plain)
    record_tree:add(pf_post_record_body_len, #body)
    record_tree:add(pf_post_record_filler_len, filler_len)
    if filler_hex ~= "" then
        record_tree:add(pf_post_record_filler_hex, filler_hex)
    end
    if sha1_hex ~= "" then
        record_tree:add(pf_post_record_sha1, sha1_hex)
    end
    record_tree:add(pf_post_plain_hex, hex_bytes(body, apple_ss.prefs.max_preview))
    record_tree:add(pf_post_plain_ascii, ascii_preview(body, apple_ss.prefs.max_preview))

    local guess = classify_rfb_payload(body, direction)
    if #body > 0 then
        record_tree:add(pf_post_guess, string.format("first_byte=0x%02x %s", body:byte(1), guess))
    else
        record_tree:add(pf_post_guess, guess)
    end

    if direction == "server" and body:byte(1) == 0 then
        parse_framebuffer_update(record_tree, body)
    elseif direction == "client" and body:byte(1) == 0 then
        parse_set_pixel_format(record_tree, body)
    elseif direction == "client" and body:byte(1) == 2 then
        parse_set_encodings(record_tree, body)
    elseif direction == "client" and body:byte(1) == 3 then
        parse_framebuffer_update_request(record_tree, body)
    elseif direction == "client" and body:byte(1) == 0x08 then
        parse_scale_factor_message(record_tree, body)
    elseif direction == "client" and body:byte(1) == 0x0d then
        parse_set_display_message(record_tree, body)
    elseif direction == "client" and body:byte(1) == 0x10 then
        parse_set_mode_message(record_tree, body)
    elseif direction == "client" and body:byte(1) == 9 then
        parse_auto_framebuffer_update(record_tree, body)
    elseif direction == "client" and body:byte(1) == 0x15 then
        parse_auto_pasteboard_command(record_tree, body)
    end

    if filler_len > 0 then
        record_tree:add(
            pf_post_rect_note,
            string.format(
                "record trailer contains %u filler byte(s) before trailing SHA1; native traces show these bytes vary by record and should not be treated as generic ignorable padding",
                filler_len
            )
        )
    end
end

local function add_rekeyed_cbc_tree(tree, st, payload, direction, pinfo)
    if st.cbc_key_hex == nil then
        return false
    end

    local pending_key = (direction == "server") and "server_cbc_pending" or "client_cbc_pending"
    local index_key = (direction == "server") and "server_cbc_record_index" or "client_cbc_record_index"
    local iv_hex = (direction == "server") and st.server_cbc_iv_hex or st.client_cbc_iv_hex
    if iv_hex == nil then
        return false
    end

    local pending = (not pinfo.visited) and (st[pending_key] or "") or ""
    local combined_payload = payload
    if not pinfo.visited and pending ~= "" then
        combined_payload = pending .. payload
    end

    local post_tree = tree:add(apple_ss, "Apple Screen Sharing Post-Auth")
    post_tree:add(pf_phase, "post-auth")
    post_tree:add(pf_post_mode, "aes-128-cbc-record-layer")
    post_tree:add(pf_post_payload_len, #combined_payload)
    post_tree:add(pf_post_cbc_key, st.cbc_key_hex)
    post_tree:add(pf_post_cbc_server_iv, st.server_cbc_iv_hex or "")
    post_tree:add(pf_post_cbc_client_iv, st.client_cbc_iv_hex or "")
    if pending ~= "" then
        post_tree:add(
            pf_post_rect_note,
            string.format("prepended %u buffered ciphertext byte(s) from previous TCP segment", #pending)
        )
    end

    local off = 0
    local record_index = (not pinfo.visited) and (st[index_key] or 0) or 0
    local start_index = record_index
    local current_iv_hex = iv_hex
    while off + 2 <= #combined_payload do
        local cipher_len = be_u16(combined_payload, off)
        if cipher_len == nil then
            break
        end
        if cipher_len == 0 then
            post_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Zero ciphertext length in CBC record stream")
            break
        end
        if (cipher_len % 16) ~= 0 then
            post_tree:add_expert_info(PI_MALFORMED, PI_WARN, string.format("CBC record length %d is not 16-byte aligned", cipher_len))
            break
        end
        if off + 2 + cipher_len > #combined_payload then
            post_tree:add_expert_info(
                PI_UNDECODED,
                PI_NOTE,
                string.format("Buffered partial CBC record; need %u more byte(s)", off + 2 + cipher_len - #combined_payload)
            )
            break
        end

        record_index = record_index + 1
        local cipher_block = combined_payload:sub(off + 3, off + 2 + cipher_len)
        local plain, err = decrypt_with_openssl("aes-128-cbc", st.cbc_key_hex, current_iv_hex, cipher_block)
        if plain == nil then
            post_tree:add_expert_info(PI_UNDECODED, PI_NOTE, "CBC decrypt failed: " .. tostring(err))
            break
        end

        add_cbc_record_tree(post_tree, st, direction, off, record_index, cipher_block, plain)
        current_iv_hex = hex_bytes(cipher_block:sub(#cipher_block - 15, #cipher_block))
        off = off + 2 + cipher_len
    end

    if not pinfo.visited then
        st[pending_key] = combined_payload:sub(off + 1)
        st[index_key] = record_index
        if direction == "server" then
            st.server_cbc_iv_hex = current_iv_hex
        else
            st.client_cbc_iv_hex = current_iv_hex
        end
    end
    if record_index == start_index then
        return #combined_payload > 0
    end
    return true
end

local function maybe_add_post_auth(tree, st, payload, pinfo)
    if not st.server_init_seen then
        return
    end

    local base_key_hex = normalize_hex(apple_ss.prefs.session_key_hex)
    if base_key_hex ~= "" and not valid_hex_n(base_key_hex, 32) then
        local subtree = tree:add(apple_ss, "Apple Screen Sharing Post-Auth")
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Invalid session_key_hex preference; expected 16-byte AES key in hex")
        return
    end
    ensure_stream_base_key(st)

    local srcport = pinfo.src_port
    local is_server = tonumber(tostring(srcport)) == 5900
    local direction = is_server and "server" or "client"
    if add_rekeyed_cbc_tree(tree, st, payload, direction, pinfo) then
        return
    end

    if base_key_hex == "" then
        return
    end

    local mode_pref = normalize_hex(is_server and apple_ss.prefs.server_mode or apple_ss.prefs.client_mode)
    local offset = is_server and apple_ss.prefs.server_offset or apple_ss.prefs.client_offset

    local post_tree = tree:add(apple_ss, "Apple Screen Sharing Post-Auth")
    post_tree:add(pf_phase, "post-auth")

    if mode_pref == "none" then
        post_tree:add(pf_post_mode, "disabled")
        return
    end

    if mode_pref == "auto" or mode_pref == "" then
        add_candidate_tree(post_tree, "aes-128-ecb", offset, payload, base_key_hex, direction)
        add_candidate_tree(post_tree, "aes-128-cbc-zero-iv", offset, payload, base_key_hex, direction, string.rep("0", 32))
    elseif mode_pref == "aes-128-ecb" then
        add_candidate_tree(post_tree, "aes-128-ecb", offset, payload, base_key_hex, direction)
    elseif mode_pref == "aes-128-cbc-zero-iv" then
        add_candidate_tree(post_tree, "aes-128-cbc-zero-iv", offset, payload, base_key_hex, direction, string.rep("0", 32))
    else
        post_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown decrypt mode preference: " .. mode_pref)
    end
end

local function classify_payload(payload, st)
    if payload:sub(1, 4) == "RFB " then
        return "protocol_version"
    end
    if #payload >= 2 and payload:byte(1) + 1 == #payload then
        return "security_types"
    end
    if #payload >= 15 and payload:byte(1) == 0x21 and payload:sub(8, 11) == "RSA1" then
        return "rsa1_client_packet1"
    end
    if #payload >= 14 and payload:sub(7, 10) == "RSA1" then
        return "rsa1_client_packet"
    end
    if #payload == 4 and not st.server_init_seen then
        return "security_result"
    end
    if #payload == 1 and not st.server_init_seen then
        return "client_init"
    end
    if #payload >= 24 and st.client_init_seen and not st.server_init_seen then
        return "server_init"
    end
    if st.server_init_seen and #payload >= 52 and be_u32(payload, 12) == 0x44f then
        return "encode_encryption_info"
    end
    if st.server_init_seen and #payload >= 8 and payload:byte(1) == 0x12 then
        return "set_encryption_message"
    end
    if st.server_init_seen and #payload >= 0x42 and payload:byte(1) == 0x21 then
        return "viewer_info"
    end
    if st.server_init_seen and #payload >= 14 and payload:byte(1) == 0x1d then
        return "set_display_configuration"
    end
    if #payload >= 14 and be_u32(payload, 0) == (#payload - 4) then
        local inner_len = be_u32(payload, 10)
        local body = payload:sub(15)
        if inner_len ~= nil and #body == inner_len then
            if blob_parse_ok("%c%m%m%o%m%q%s", body) then
                return "srp_server_challenge_packet"
            end
            if blob_parse_ok("%o%o%s%u", body) then
                return "srp_server_final_packet"
            end
        end
        if st.phase == "rsa1_client_packet1" or st.phase == "rsa1_client_packet" then
            return "srp_server_challenge_packet"
        end
        if st.phase == "srp_server_challenge_packet" or st.phase == "rsa1_client_packet" then
            return "srp_server_final_packet"
        end
    end
    return "unknown"
end

function apple_ss.dissector(tvb, pinfo, tree)
    if pinfo.number == 1 and not pinfo.visited then
        reset_state()
    end

    if vnc_dissector ~= nil then
        vnc_dissector:call(tvb, pinfo, tree)
    end

    if tvb:len() == 0 then
        return
    end
    local payload = tvb:raw(0, tvb:len())

    local tcp_stream = f_tcp_stream()
    if tcp_stream == nil then
        return
    end
    local stream_id = tonumber(tostring(tcp_stream))
    if stream_id == nil then
        return
    end

    local st = get_stream_state(stream_id)
    local phase = classify_payload(payload, st)
    local root = tree:add(apple_ss, "Apple Screen Sharing Auth33")
    root:add(pf_stream, stream_id)
    root:add(pf_phase, phase)

    local srcport = pinfo.src_port
    local dstport = pinfo.dst_port

    if phase == "protocol_version" then
        if not pinfo.visited then
            st.phase = phase
        end
        root:append_text(": " .. payload:gsub("\n", ""))
        return
    end

    if phase == "security_types" then
        root:add(pf_security_count, payload:byte(1))
        for i = 2, #payload do
            root:add(pf_security_type, payload:byte(i))
        end
        if not pinfo.visited then
            st.phase = phase
        end
        return
    end

    if phase == "rsa1_client_packet1" or phase == "rsa1_client_packet" then
        local base = (phase == "rsa1_client_packet1") and 1 or 0
        if phase == "rsa1_client_packet1" then
            root:add(pf_security_selected, payload:byte(1))
        end
        root:add(pf_rsa1_len, be_u32(payload, base))
        root:add(pf_rsa1_version, be_u16(payload, base + 4))
        root:add(pf_rsa1_magic, payload:sub(base + 7, base + 10))
        root:add(pf_rsa1_authtype, be_u16(payload, base + 10))
        root:add(pf_rsa1_aux, be_u16(payload, base + 12))
        local body = payload:sub(base + 15)
        root:add(pf_rsa1_body_len, #body)
        if phase == "rsa1_client_packet1" then
            root:add(pf_rsa1_body_nz, non_zero_count(body))
        end
        if not pinfo.visited then
            st.phase = phase
        end
        return
    end

    if phase == "srp_server_challenge_packet" then
        root:add(pf_srp_total_len, be_u32(payload, 0))
        root:add(pf_srp_step, be_u32(payload, 4))
        root:add(pf_srp_x, be_u16(payload, 8))
        root:add(pf_srp_inner_len, be_u32(payload, 10))
        local body = payload:sub(15)
        local vals = parse_fmt_blob("%c%m%m%o%m%q%s", body)
        if vals ~= nil then
            root:add(pf_srp_flags, vals[1]:byte(1) or 0)
            root:add(pf_srp_n_len, #vals[2])
            root:add(pf_srp_g, vals[3])
            root:add(pf_srp_salt, vals[4])
            root:add(pf_srp_b_len, #vals[5])
            root:add(pf_srp_kdf_iters, vals[6])
            root:add(pf_srp_options, vals[7])
        end
        if not pinfo.visited then
            st.phase = phase
        end
        return
    end

    if phase == "srp_server_final_packet" then
        root:add(pf_srp_total_len, be_u32(payload, 0))
        root:add(pf_srp_step, be_u32(payload, 4))
        root:add(pf_srp_x, be_u16(payload, 8))
        root:add(pf_srp_inner_len, be_u32(payload, 10))
        if not pinfo.visited then
            st.phase = phase
        end
        return
    end

    if phase == "security_result" then
        local result = be_u32(payload, 0)
        root:add(pf_security_result, result)
        if not pinfo.visited then
            st.phase = phase
            st.auth_complete = (result == 0)
        end
        return
    end

    if phase == "client_init" then
        local ci = payload:byte(1)
        root:add(pf_client_init, ci)
        root:add(pf_client_init_shared, ci)
        root:add(pf_client_init_bit6, ci)
        root:add(pf_client_init_bit7, ci)
        if not pinfo.visited then
            st.phase = phase
            st.client_init_seen = true
        end
        return
    end

    if phase == "server_init" then
        root:add(pf_server_width, be_u16(payload, 0))
        root:add(pf_server_height, be_u16(payload, 2))
        local name_len = be_u32(payload, 20)
        root:add(pf_server_name_len, name_len)
        if name_len ~= nil and #payload >= 24 + name_len then
            root:add(pf_server_name, payload:sub(25, 24 + name_len))
        end
        if not pinfo.visited then
            st.phase = phase
            st.server_init_seen = true
        end
        maybe_add_post_auth(root, st, payload, pinfo)
        return
    end

    if phase == "set_encryption_message" then
        local msg_id = payload:byte(1)
        root:add(pf_post_msg_id, msg_id)
        root:add(pf_post_msg_name, post_auth_message_name(msg_id))
        root:add(pf_post_msg_len, #payload)
        if #payload >= 12 then
            local command = be_u16(payload, 4) or 0
            local method_count = be_u16(payload, 6) or 0
            root:add(pf_post_guess,
                     string.format("SetEncryptionMessage command=%u method_count=%u", command, method_count))
        elseif #payload >= 8 then
            local command = be_u16(payload, 2) or 0
            local value = be_u16(payload, 4) or 0
            root:add(pf_post_guess,
                     string.format("SetEncryptionMessage short-form command=%u value=%u", command, value))
        end
        return
    end

    if phase == "viewer_info" then
        local msg_id = payload:byte(1)
        root:add(pf_post_msg_id, msg_id)
        root:add(pf_post_msg_name, post_auth_message_name(msg_id))
        root:add(pf_post_msg_len, be_u16(payload, 2) or 0)
        return
    end

    if phase == "set_display_configuration" then
        local msg_id = payload:byte(1)
        local name_len = be_u16(payload, 12)
        root:add(pf_post_msg_id, msg_id)
        root:add(pf_post_msg_name, post_auth_message_name(msg_id))
        root:add(pf_post_msg_len, be_u16(payload, 2) or 0)
        if name_len ~= nil then
            root:add(pf_post_name_len, name_len)
            if #payload >= 14 + name_len then
                local name = payload:sub(15, 14 + name_len):gsub("%z+$", "")
                root:add(pf_post_display_name, name)
            end
        end
        return
    end

    if phase == "encode_encryption_info" then
        local encinfo_payload = payload:sub(1, 52)
        local trailing_payload = payload:sub(53)
        local wrap_key_hex = ensure_stream_base_key(st)
        local counter = be_u32(encinfo_payload, 16) or 0
        local block1 = encinfo_payload:sub(21, 36)
        local block2 = encinfo_payload:sub(37, 52)

        root:add(pf_post_msg_id, 0x44f)
        root:add(pf_post_msg_name, post_auth_message_name(0x44f))
        root:add(pf_post_msg_len, #encinfo_payload)
        root:add(pf_post_rfb_msg, encinfo_payload:byte(1))
        root:add(pf_post_rect_count, be_u16(encinfo_payload, 2) or 0)
        root:add(pf_post_rect_x, be_u16(encinfo_payload, 4) or 0)
        root:add(pf_post_rect_y, be_u16(encinfo_payload, 6) or 0)
        root:add(pf_post_rect_w, be_u16(encinfo_payload, 8) or 0)
        root:add(pf_post_rect_h, be_u16(encinfo_payload, 10) or 0)
        root:add(pf_post_rect_encoding, be_u32(encinfo_payload, 12) or 0)
        root:add(pf_post_encinfo_counter, counter)
        root:add(pf_post_encinfo_block1, block1)
        root:add(pf_post_encinfo_block2, block2)
        if wrap_key_hex ~= nil then
            root:add(pf_post_wrap_key, wrap_key_hex)
            local plain1, err1 = decrypt_with_openssl("aes-128-ecb", wrap_key_hex, nil, block1)
            local plain2, err2 = decrypt_with_openssl("aes-128-ecb", wrap_key_hex, nil, block2)
            if plain1 ~= nil and plain2 ~= nil and #plain1 >= 16 and #plain2 >= 16 then
                local next_key_hex = hex_bytes(plain1:sub(1, 16))
                local next_iv_hex = hex_bytes(plain2:sub(1, 16))
                root:add(pf_post_next_key, next_key_hex)
                root:add(pf_post_next_iv, next_iv_hex)
                if not pinfo.visited then
                    st.rekey_counter = st.rekey_counter + 1
                    st.wrap_key_hex = next_key_hex
                    st.cbc_key_hex = next_key_hex
                    st.server_cbc_iv_hex = next_iv_hex
                    st.client_cbc_iv_hex = next_iv_hex
                    st.cbc_base_seq = counter > 0 and (counter - 1) or 0
                end
                root:add(pf_post_cbc_key, st.cbc_key_hex or next_key_hex)
                root:add(pf_post_cbc_server_iv, st.server_cbc_iv_hex or next_iv_hex)
                root:add(pf_post_cbc_client_iv, st.client_cbc_iv_hex or next_iv_hex)
            else
                root:add_expert_info(
                    PI_UNDECODED,
                    PI_NOTE,
                    "Failed to derive next transport key/IV from EncodeEncryptionInfo: "
                        .. tostring(err1 or err2)
                )
            end
        end
        if #trailing_payload > 0 then
            root:add(
                pf_post_rect_note,
                string.format("same TCP segment contains %u trailing encrypted byte(s) after EncodeEncryptionInfo", #trailing_payload)
            )
            add_rekeyed_cbc_tree(root, st, trailing_payload, "server", pinfo)
        end
        return
    end

    maybe_add_post_auth(root, st, payload, pinfo)
end

DissectorTable.get("tcp.port"):add(5900, apple_ss)
