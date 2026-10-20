"""
项目名称：TCP/UDP Header Hex Parser
中文名称：TCP/UDP 报文头十六进制解析器
课程：工程导论 期末 AI 辅助工程实践

功能：
    1. 输入十六进制报文头，自动清洗空格、换行、冒号、短横线、逗号、下划线、0x 前缀
    2. 校验空输入、非法字符、奇数长度
    3. UDP 基础头解析：源端口、目的端口、长度、校验和
    4. TCP 基础头解析：源端口、目的端口、序列号、确认号、数据偏移、
       保留位、NS、标志位、窗口、校验和、紧急指针
    5. 显示 TCP 头部长度和置位标志
    6. 一键载入 UDP / TCP 示例，session_state 保存输入和协议
    7. 边界处理：
       - TCP 数据偏移 < 5 直接报错
       - UDP 长度字段 < 8 直接报错
       - UDP 长度字段与实际输入不一致时 warning
       - TCP 头部长度超过实际输入时 warning
       - 输入全为 0x00 时 warning
       - 输入超过 100 字节时提示
       - 解析主流程 try/except 兜底
    8. 示例库代码默认注释，仅供开发测试使用

运行方式：
    pip install streamlit pandas
    streamlit run app.py
"""

import struct
import pandas as pd
import streamlit as st

# ============================================================
# 页面基础配置
# ============================================================
st.set_page_config(
    page_title="TCP/UDP 报文头十六进制解析器",
    page_icon="📡",
    layout="wide",
)

st.title("📡 TCP/UDP 报文头十六进制解析器")
st.caption("《工程导论》期末 AI 辅助工程实践作品")


# ============================================================
# 工具函数：十六进制字符串清洗与校验
# ============================================================
def clean_hex(s):
    """
    清洗并校验十六进制字符串。

    参数：
        s: 用户输入的原始字符串

    返回：
        (cleaned, error)
        cleaned: 清洗后的大写十六进制字符串；有错时为空字符串
        error:   错误信息；无错时为 None
    """
    if s is None:
        return "", "请输入十六进制报文"

    s = s.strip()
    if not s:
        return "", "请输入十六进制报文"

    # 去掉 0x / 0X 前缀
    s = s.replace("0x", "").replace("0X", "")

    # 去掉常见分隔符
    for ch in [" ", "\n", "\r", "\t", ":", "-", ",", "_"]:
        s = s.replace(ch, "")

    if not s:
        return "", "请输入十六进制报文"

    if len(s) % 2 != 0:
        return "", "十六进制字符串长度必须为偶数"

    try:
        bytes.fromhex(s)
    except ValueError:
        return "", "包含非法十六进制字符，只能包含 0-9、A-F"

    return s.upper(), None


# ============================================================
# UDP 基础头解析
# ============================================================
def parse_udp(data):
    """
    解析 UDP 基础头，固定 8 字节。

    返回：
        (fields, extra, error)
        fields: 字段列表
        extra:  补充信息列表
        error:  错误信息；成功返回 None
    """
    if len(data) < 8:
        return None, None, f"UDP 头至少需要 8 字节，当前只有 {len(data)} 字节"

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])

    # 边界检查：UDP 长度字段不能小于最小头部 8 字节
    if length < 8:
        return None, None, (
            f"UDP 长度字段为 {length}，小于最小头部 8 字节，输入不合法。"
            f"请检查报文头是否正确。"
        )

    fields = [
        ("源端口",   0, 2, data[0:2].hex(" ").upper(), src_port,  "发送方端口"),
        ("目的端口", 2, 2, data[2:4].hex(" ").upper(), dst_port,  "接收方端口"),
        ("长度",     4, 2, data[4:6].hex(" ").upper(), length,    "UDP 总长度（字节）"),
        ("校验和",   6, 2, data[6:8].hex(" ").upper(), checksum,  "差错校验字段，本工具仅显示不验证"),
    ]

    extra = [
        ("UDP 头部长度", 8, "字节"),
    ]

    # 边界检查：长度字段与实际输入字节数不一致
    if length != len(data):
        extra.append((
            "⚠️ 长度字段校验",
            f"长度字段是 {length}，但实际输入 {len(data)} 字节，"
            f"可能只截了头部，或输入包含额外载荷",
            "",
        ))

    return fields, extra, None


# ============================================================
# TCP 基础头解析
# ============================================================
def parse_tcp(data):
    """
    解析 TCP 基础头，固定 20 字节。

    返回：
        (fields, extra, error)
        fields: 字段列表
        extra:  补充信息列表
        error:  错误信息；成功返回 None
    """
    if len(data) < 20:
        return None, None, f"TCP 头至少需要 20 字节，当前只有 {len(data)} 字节"

    (src_port, dst_port, seq, ack,
     offset_reserved_ns, flags, window, checksum, urgent) = \
        struct.unpack("!HHIIBBHHH", data[:20])

    data_offset = (offset_reserved_ns >> 4) & 0x0F
    reserved    = (offset_reserved_ns >> 1) & 0x07
    ns          = offset_reserved_ns & 0x01
    header_len  = data_offset * 4

    # 边界检查：TCP 头部最小 20 字节，数据偏移必须 >= 5
    if data_offset < 5:
        return None, None, (
            f"TCP 数据偏移字段无效：data_offset = {data_offset}，"
            f"最小应为 5（对应 20 字节头部）。"
            f"当前输入可能不是 TCP 报文头，或你选的协议不对，请检查。"
        )

    flag_defs = [
        ("CWR", 0x80), ("ECE", 0x40), ("URG", 0x20), ("ACK", 0x10),
        ("PSH", 0x08), ("RST", 0x04), ("SYN", 0x02), ("FIN", 0x01),
    ]
    flags_on = [name for name, mask in flag_defs if flags & mask]
    flags_str = ", ".join(flags_on) if flags_on else "无"

    fields = [
        ("源端口",   0,  2, data[0:2].hex(" ").upper(),  src_port,   "发送方端口"),
        ("目的端口", 2,  2, data[2:4].hex(" ").upper(),  dst_port,   "接收方端口"),
        ("序列号",   4,  4, data[4:8].hex(" ").upper(),  seq,        "TCP 序列号"),
        ("确认号",   8,  4, data[8:12].hex(" ").upper(), ack,        "TCP 确认号"),
        ("数据偏移", 12, 1, data[12:13].hex(" ").upper(), data_offset, "单位 4 字节，头部长度 = 数据偏移 × 4"),
        ("保留位",   12, 1, data[12:13].hex(" ").upper(), reserved,   "保留字段"),
        ("NS",       12, 1, data[12:13].hex(" ").upper(), ns,         "ECN 随机数摘要"),
        ("标志位",   13, 1, data[13:14].hex(" ").upper(), flags,      f"置位标志：{flags_str}"),
        ("窗口",     14, 2, data[14:16].hex(" ").upper(), window,     "接收窗口大小"),
        ("校验和",   16, 2, data[16:18].hex(" ").upper(), checksum,   "TCP 校验和，本工具仅显示不验证"),
        ("紧急指针", 18, 2, data[18:20].hex(" ").upper(), urgent,     "紧急指针"),
    ]

    extra = [
        ("TCP 头部长度", header_len, "字节"),
        ("置位标志", flags_str, ""),
    ]

    # 边界检查：头部长度超过实际输入
    if header_len > len(data):
        extra.append((
            "⚠️ 头部长度校验",
            f"数据偏移字段声称头部长度为 {header_len} 字节，"
            f"但实际输入只有 {len(data)} 字节，输入可能不完整",
            "",
        ))

    return fields, extra, None


# ============================================================
# 示例按钮回调
# ============================================================
def load_udp_example():
    """载入 UDP 示例，并自动切换到 UDP 协议"""
    st.session_state.hex_input = "1F900035002A0000"
    st.session_state.protocol = "UDP"


def load_tcp_example():
    """载入 TCP 示例，并自动切换到 TCP 协议"""
    st.session_state.hex_input = "3039005000000001000000005002FFFF12340000"
    st.session_state.protocol = "TCP"


# ============================================================
# 示例库（供开发测试使用，正式界面不显示）
# 说明：以下代码默认注释掉，不影响正式界面；
#      如需测试示例库功能，取消下面整段注释即可。
# ============================================================
# EXAMPLES = {
#     "UDP 正常解析":           ("UDP", "1F900035002A0000", "源端口 8080，目的端口 53，长度 42"),
#     "TCP 正常解析（SYN）":     ("TCP", "3039005000000001000000005002FFFF12340000", "源端口 12345，目的端口 80，标志位 SYN"),
#     "TCP 多标志位（SYN+ACK）": ("TCP", "3039005000000001000000005012FFFF12340000", "标志位 SYN, ACK"),
#     "UDP 长度不足":           ("UDP", "1F900035", "只有 4 字节，应提示至少 8 字节"),
#     "TCP 长度不足":           ("TCP", "3039005000000001", "只有 8 字节，应提示至少 20 字节"),
#     "非法字符":               ("UDP", "1F90GG35", "应提示包含非法字符"),
#     "奇数长度":               ("UDP", "1F900035002A000", "应提示长度必须为偶数"),
#     "带冒号分隔符":           ("UDP", "1F:90:00:35:00:2A:00:00", "冒号分隔也能正常解析"),
# }
#
#
# def on_example_change():
#     """
#     下拉框选择变化时自动载入示例。
#     用 on_change 回调，避免直接修改已创建 widget 的 state 报错。
#     """
#     name = st.session_state.get("example_choice", "请选择...")
#     if name == "请选择..." or name not in EXAMPLES:
#         return
#     proto, hex_val, _desc = EXAMPLES[name]
#     st.session_state.hex_input = hex_val
#     st.session_state.protocol = proto


# ============================================================
# 初始化 session_state
# ============================================================
if "hex_input" not in st.session_state:
    st.session_state.hex_input = ""
if "protocol" not in st.session_state:
    st.session_state.protocol = "UDP"


# ============================================================
# 界面布局：输入区
# ============================================================
col_input, col_proto = st.columns([3, 1])

with col_input:
    hex_input = st.text_area(
        "输入十六进制报文头",
        height=120,
        placeholder="请输入十六进制报文头",
        key="hex_input",
    )

with col_proto:
    protocol = st.selectbox("选择协议", ["UDP", "TCP"], key="protocol")

# ============================================================
# 按钮区
# ============================================================
col_btn1, col_btn2, col_btn3, col_btn4 = st.columns([1, 1.5, 1.5, 2])

with col_btn1:
    parse_clicked = st.button("开始解析", type="primary")

with col_btn2:
    st.button("载入 UDP 示例", on_click=load_udp_example)

with col_btn3:
    st.button("载入 TCP 示例", on_click=load_tcp_example)

with col_btn4:
    st.empty()

# ============================================================
# 示例库（展开后可一键载入示例，正式界面不显示）
# 说明：如需测试示例库功能，取消下面整段注释即可。
# ============================================================
# with st.expander("📚 示例库", expanded=False):
#     st.selectbox(
#         "选择示例",
#         ["请选择..."] + list(EXAMPLES.keys()),
#         key="example_choice",
#         on_change=on_example_change,
#         help="选中后会立即把十六进制例子填到上方输入框，并自动切换协议",
#     )

# ============================================================
# 解析逻辑
# ============================================================
if parse_clicked:
    cleaned, err = clean_hex(hex_input)

    if err:
        st.error(err)
    else:
        # 兜底：任何未预料异常都转成友好提示
        try:
            data = bytes.fromhex(cleaned)

            if protocol == "UDP":
                fields, extra, err = parse_udp(data)
            else:
                fields, extra, err = parse_tcp(data)
        except Exception as e:
            st.error(f"解析过程中出现未预料的错误：{e}")
            st.stop()

        if err:
            st.error(err)
        else:
            st.success(f"解析成功：协议 {protocol}，输入共 {len(data)} 字节。")

            # 额外友好提示：全零输入
            if all(b == 0 for b in data):
                st.warning("输入全部为 0x00，请确认是否误粘贴或占位数据。")

            # 额外友好提示：超长输入
            if len(data) > 100:
                st.info(f"输入共 {len(data)} 字节，长度较长，可能包含完整报文而非仅报文头。")

            # 字段表格：st.table 自动换行，说明列完整显示
            df = pd.DataFrame(
                fields,
                columns=["字段", "偏移(字节)", "长度(字节)", "原始十六进制", "解析值", "说明"],
            )
            st.table(df)

            # 补充信息（含边界检查 warning）
            st.subheader("补充信息")
            for name, value, unit in extra:
                if name.startswith("⚠️"):
                    st.warning(f"{name}：{value}")
                else:
                    st.write(f"**{name}**：{value} {unit}")

            # 超长提示
            if protocol == "UDP" and len(data) > 8:
                st.info("输入超过 8 字节，超出部分为 UDP 载荷，本工具当前只解析 8 字节头部。")
            if protocol == "TCP" and len(data) > 20:
                st.info("输入超过 20 字节，超出部分可能是 TCP 选项或载荷，本工具当前只解析基础 20 字节头部。")


# ============================================================
# 页脚说明
# ============================================================
st.divider()
st.caption("本工具仅解析基础头部，不验证校验和，不解析选项和载荷。")