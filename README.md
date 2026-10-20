# TCP/UDP Header Hex Parser

基于 Python + Streamlit 的 TCP/UDP 报文头十六进制解析器。

## 功能
- 输入十六进制报文头，自动解析 UDP 或 TCP 字段
- 支持空格、冒号、0x 等格式
- 错误输入友好提示
- 显示 TCP 标志位（SYN、ACK 等）

## 环境要求
- Python >= 3.10

## 运行方式
1. 安装依赖：
   pip install -r requirements.txt
2. 启动：
   streamlit run app.py
3. 浏览器打开 http://localhost:8501

## 示例
- UDP：1F900035002A0000
- TCP：3039005000000001000000005002FFFF12340000

## 说明
本工具仅解析基础头部，不验证校验和，不解析选项和载荷。