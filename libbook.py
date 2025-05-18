import argparse
import sys
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import uuid
from datetime import datetime, timedelta
from collections import defaultdict

# ========== 座位码到设备ID映射 ==========
seat_mapping = {}
seat_room_mapping = {}  # 例：100653065: ('2B254', '二楼-开放式学习空间B')

room_defs = [
    ("二楼-开放式学习空间B", "2B", "2B001", "2B354", 100652812),
    ("三楼-图书学习空间A", "3A", "3A001", "3A124", 100653166),
    ("三楼-图书学习空间B", "3B", "3B001", "3B188", 100653290),
    ("四楼-期刊学习空间A", "4A", "4A001", "4A172", 100653478),
    ("四楼-期刊学习空间B", "4B", "4B001", "4B244", 100653650),
    ("五楼-交互式学习空间A", "5A", "5A001", "5A131", 100653894),
    ("五楼-交互式学习空间B", "5B", "5B001", "5B184", 100654025),
]

def register_range_with_room(room_name, prefix, start_code, end_code, start_id):
    num_seats = int(end_code[-3:]) - int(start_code[-3:]) + 1
    for i in range(num_seats):
        code_num = int(start_code[-3:]) + i
        code = f"{prefix}{code_num:03d}".upper()
        seat_id = start_id + i
        seat_mapping[code] = seat_id
        seat_room_mapping[seat_id] = (code, room_name)

for room_name, prefix, start_code, end_code, start_id in room_defs:
    register_range_with_room(room_name, prefix, start_code, end_code, start_id)
def register_range(prefix, start_code, end_code, start_id):
    num_seats = int(end_code[-3:]) - int(start_code[-3:]) + 1
    for i in range(num_seats):
        code_num = int(start_code[-3:]) + i
        code = f"{prefix}{code_num:03d}"
        seat_mapping[code.upper()] = start_id + i

register_range('2B', '2B001', '2B354', 100652812)
register_range('3A', '3A001', '3A124', 100653166)
register_range('3B', '3B001', '3B188', 100653290)
register_range('4A', '4A001', '4A172', 100653478)
register_range('4B', '4B001', '4B244', 100653650)
register_range('5A', '5A001', '5A131', 100653894)
register_range('5B', '5B001', '5B184', 100654025)

# ========== 默认值 ==========
DEFAULT_LOGON = "your_username"
DEFAULT_PASSWORD = "your_password"
DEFAULT_SEATS = ["2B254"]

def get_default_times():
    tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
    return f"{tomorrow} 10:00:00", f"{tomorrow} 22:00:00"

# ========== argparse 参数解析 ==========
def parse_args():
    default_begin, default_end = get_default_times()
    room_seats = defaultdict(list)
    for seat in seat_mapping:
        room = seat[:2]  # 假设房间号是座位号前两位
        room_seats[room].append(seat)

    lines = []
    for room in sorted(room_seats):
        seats = sorted(room_seats[room])
        lines.append(f"{room}: {seats[0]}–{seats[-1]}")
    help_seats = '\n'.join(lines)
    parser = argparse.ArgumentParser(
        description="吉林大学图书馆座位预约脚本，支持命令行参数输入。"
    )
    parser.add_argument("--logon_name", type=str, help=f"学号或用户名 (默认: {DEFAULT_LOGON})")
    parser.add_argument("--raw_password", type=str, help=f"明文密码 (默认是身份证后六位)")
    parser.add_argument(
    "--seats",
    type=str,
    nargs='+',
    help=f"座位码列表，如：2B254，不区分大小写。\n可用座位:\n{help_seats}\n(默认: {' '.join(DEFAULT_SEATS)})"
)
    parser.add_argument("--resvBeginTime", type=str, default=default_begin, help=f"预约开始时间，格式如：{default_begin}")
    parser.add_argument("--resvEndTime", type=str, default=default_end, help=f"预约结束时间，格式如：{default_end}")
    return parser.parse_args()

# ========== 交互式输入 ==========
def interactive_input():
    print("==== 交互式模式 ====")
    default_begin, default_end = get_default_times()
    logon_name = input(f"请输入用户名（学号）（回车使用默认 {DEFAULT_LOGON}）：").strip() or DEFAULT_LOGON
    raw_password = input(f"请输入密码（身份证后六位）（回车使用默认值）：").strip() or DEFAULT_PASSWORD
    print("示例座位码: 2B001, 3A050, 4B100 …")
    seats_input = input(f"请输入座位码列表，以空格分隔（回车使用默认 {' '.join(DEFAULT_SEATS)}）：").strip()
    seats = seats_input.split() if seats_input else DEFAULT_SEATS
    resvBeginTime = input(f"预约开始时间（格式 YYYY-MM-DD HH:MM:SS，回车使用默认 {default_begin}）：").strip() or default_begin
    resvEndTime = input(f"预约结束时间（格式 YYYY-MM-DD HH:MM:SS，回车使用默认 {default_end}）：").strip() or default_end
    return logon_name, raw_password, seats, resvBeginTime, resvEndTime

# ===== 主流程 =====
if __name__ == '__main__':
    if len(sys.argv) == 1:
        logon_name, raw_password, seats, resvBeginTime, resvEndTime = interactive_input()
    else:
        args = parse_args()
        logon_name = args.logon_name or DEFAULT_LOGON
        raw_password = args.raw_password or DEFAULT_PASSWORD
        seats = args.seats or DEFAULT_SEATS
        resvBeginTime = args.resvBeginTime
        resvEndTime = args.resvEndTime

    print(f"用户名: {logon_name}")
    print(f"密码: {'*' * len(raw_password)}")
    print(f"预约时间: {resvBeginTime} 至 {resvEndTime}")

    # 转换座位码到设备ID
    resvDev = []
    print("预约座位：")
    for code in seats:
        key = code.upper()
        if key in seat_mapping:
            seat_id = seat_mapping[key]
            resvDev.append(seat_id)
            seat_code, room_name = seat_room_mapping[seat_id]
            print(f"  - {seat_code}（{room_name}）")
        else:
            print(f"❌ 无效座位码: {code}")
            sys.exit(1)

    # ========== 初始化会话 ==========
    session = requests.Session()
    ic_cookie = str(uuid.uuid4())
    session.cookies.set("ic-cookie", ic_cookie, domain="libzwyy.jlu.edu.cn")
    headers_common = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "http://libzwyy.jlu.edu.cn",
        "Referer": "http://libzwyy.jlu.edu.cn/",
        "lan": "1", "DNT": "1",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "sec-gpc": "1"
    }

    # ========== 获取公钥并加密密码 ==========
    print("正在获取公钥...")
    resp = session.get("http://libzwyy.jlu.edu.cn/ic-web/login/publicKey", headers=headers_common)
    resp.raise_for_status()
    data = resp.json()
    public_key_pem = data["data"]["publicKey"]
    nonce_str = data["data"]["nonceStr"]
    if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key_pem = (
            "-----BEGIN PUBLIC KEY-----\n" + public_key_pem + "\n-----END PUBLIC KEY-----"
        )
    message = f"{raw_password};{nonce_str}"
    # print(message)
    rsa_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted_bytes = cipher.encrypt(message.encode("utf-8"))
    encrypted_password = base64.b64encode(encrypted_bytes).decode("utf-8")

    # ========== 登录 ==========
    print("正在登录...")
    login_url = "http://libzwyy.jlu.edu.cn/ic-web/login/user"
    login_payload = {
        "logonName": logon_name,
        "password": encrypted_password,
        "captcha": "",
        "privacy": True,
        "consoleType": 16
    }
    login_resp = session.post(login_url, headers=headers_common, json=login_payload)
    login_data = login_resp.json()
    print(f"登录结果：{login_data.get('message')}")
    token = login_data.get("data", {}).get("token")
    appAccNo = login_data.get("data", {}).get("accNo")
    if not token or not appAccNo:
        print("❌ 登录失败，可能密码错误或其他问题")
        sys.exit(1)
    print("✅ 登录成功")

    # ========== 预约 ==========
    print("正在提交预约请求...")
    reserve_url = "http://libzwyy.jlu.edu.cn/ic-web/reserve"
    reserve_payload = {
        "sysKind": 8,
        "appAccNo": appAccNo,
        "memberKind": 1,
        "resvMember": [appAccNo],
        "resvBeginTime": resvBeginTime,
        "resvEndTime": resvEndTime,
        "testName": "",
        "captcha": "",
        "resvProperty": 0,
        "resvDev": resvDev,
        "memo": ""
    }
    headers_reserve = headers_common.copy()
    headers_reserve["token"] = token
    reserve_resp = session.post(reserve_url, headers=headers_reserve, json=reserve_payload)
    reserve_json = reserve_resp.json()
    print(f"预约结果：{reserve_json.get('message')}")
    if reserve_json.get("code") == 0:
        print("✅ 预约成功！")
    else:
        print("❌ 预约失败！")