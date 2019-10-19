do
  -- KCP Protocol
  local kcp_header_len = 24;
  local cmd_types = {
    [81] = "PUSH",
    [82] = "ACK",
    [83] = "WASK",
    [84] = "WINS",}

  local kcp_proto = Proto("KCP", "KCP Protocol");

  local kcp_conv = ProtoField.uint32("kcp.conv", "conv", base.DEC)
  local kcp_cmd = ProtoField.uint32("kcp.cmd", "cmd", base.DEC, cmd_types)
  local kcp_frg = ProtoField.uint32("kcp.frg", "frg", base.DEC)
  local kcp_wnd = ProtoField.uint32("kcp.wnd", "wnd", base.DEC)
  local kcp_ts = ProtoField.uint32("kcp.ts", "ts", base.DEC)
  local kcp_sn = ProtoField.uint32("kcp.sn", "sn", base.DEC)
  local kcp_una = ProtoField.uint32("kcp.una", "una", base.DEC)
  local kcp_len = ProtoField.uint32("kcp.len", "len", base.DEC)
  local kcp_data = ProtoField.string("kcp.data", "data")

  kcp_proto.fields = {kcp_conv, kcp_cmd, kcp_frg, kcp_wnd, kcp_ts, kcp_sn, kcp_una, kcp_len, kcp_data}

  -- 每个kcp包
  function kcp_parse(buf, pkt, root)
	local buf_len = buf:len();
    local kcp_data_len = buf(20, 4):le_uint();
	local old_str = tostring(pkt.cols.info)
	if old_str ~= "" then old_str = old_str .. "; " end
    old_str = old_str .. "sn="..buf(12,4):le_uint() ..",cmd=" .. cmd_types[buf(4,1):le_uint()] .. ",len="..kcp_data_len
	-- local cmd_type = cmd_types[buf(4,1):le_uint()]
	-- if cmd_type == "ACK" then
		-- old_str = old_str .." " .. cmd_type
	-- end
	pkt.cols.info = old_str

    local t = root:add(kcp_proto, buf(0, kcp_header_len + kcp_data_len), "KCP")
    t:add(kcp_conv, buf(0, 4):le_uint())
    t:add(kcp_cmd, buf(4, 1):le_uint())
    t:add(kcp_frg, buf(5, 1):le_uint())
    t:add(kcp_wnd, buf(6, 2):le_uint())
    t:add(kcp_ts, buf(8, 4):le_uint())
    t:add(kcp_sn, buf(12, 4):le_uint())
    t:add(kcp_una, buf(16, 4):le_uint())
    t:add(kcp_len, buf(20, 4):le_uint())
	if buf_len > kcp_header_len 
	then
		--t:add(kcp_data, buf(kcp_header_len, buf_len - kcp_header_len))
	end
  end
  
  -- UDP报文
  function kcp_proto.dissector(buf, pkt, root)
    pkt.cols.protocol = "KCP"
	pkt.cols.info = ""
	local total_len = buf:len()
	--pkt.cols.info = "total_len=".. total_len..""
	local len_offset = 0
	local rest_len = total_len
	while(rest_len >= kcp_header_len)
	do
		if(rest_len < kcp_header_len) then
			pkt.cols.info = tostring(pkt.cols.info).."; Error!!! rest_len="..rest_len.."<24"
			return
		end
		
		local kcp_data_len = buf(len_offset + 20, 4):le_uint()
		if (kcp_header_len + kcp_data_len) > rest_len then 
			pkt.cols.info = tostring(pkt.cols.info) .. "; Error!!! kcp_len=" ..kcp_header_len + kcp_data_len.. " but rest_len=".. rest_len
			return
		end
		
		local temp_buf = buf(len_offset, kcp_header_len + kcp_data_len)
		kcp_parse(temp_buf, pkt, root)
		len_offset = len_offset + kcp_header_len + kcp_data_len
		rest_len = total_len - len_offset
	end
    return true
  end

  -- 注册协议
	local udp_table = DissectorTable.get('udp.port')
	udp_table:add('21501', kcp_proto)
end
