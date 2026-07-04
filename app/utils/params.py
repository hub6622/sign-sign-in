import hashlib
import hmac
import json
import random
import re
import time
import urllib.parse

from gmssl import sm2

from app.config.common import (
    XYB_APP_ID,
    XYB_EXCLUDED_KEYS,
    XYB_KEY,
    XYB_N_HEADER,
    XYB_SM2_MODE,
    XYB_SM2_PUBLIC_KEY,
)
from app.utils.common import rand_str


def _normalize_header_token_value(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, dict, set)):
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        except TypeError:
            return str(value)
    return str(value)


def _sanitize_sign_text(value):
    return (
        str(value)
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace("<", "")
        .replace(">", "")
        .replace("&", "")
        .replace("-", "")
        .replace(r"\uD83C[\uDF00-\uDFFF]", "")
        .replace(r"\uD83D[\uDC00-\uDE4F]", "")
    )


def _normalize_security_value(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, dict, set)):
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except TypeError:
            return str(value)
    return str(value)


def _djb2(value):
    result = 5381
    for char in str(value or ""):
        result = ((result * 33) + ord(char)) & 0xFFFFFFFF
    return result


def _security_data_sign(data):
    special_char_regex = re.compile(r"[`~!@#$%^&*()+=|{}':;',\[\].<>/?~锛丂#锟?鈥︹€?*锛堬級鈥斺€?|{}銆愩€戔€橈紱锛氣€濃€溾€欍€傦紝銆侊紵]")
    raw = ""
    for key in sorted(k for k in data if k not in ("h5st", "_stk", "_ste")):
        value_text = _normalize_security_value(data[key])
        if key not in XYB_EXCLUDED_KEYS and not special_char_regex.search(value_text):
            raw += f"{key}{value_text}"
    return urllib.parse.quote(_sanitize_sign_text(raw).replace("[]", ""))


def create_security_fingerprint():
    return hashlib.md5(f"{int(time.time() * 1000)}_{random.random()}".encode("utf-8")).hexdigest()


def get_security_url_token(security_token):
    return str(_djb2(security_token))


def get_security_params(data, security_token, fingerprint):
    timestamp = int(time.time() * 1000)
    app_sign = hashlib.md5(f"{_djb2(security_token)}{fingerprint}{timestamp}{XYB_APP_ID}".encode("utf-8")).hexdigest()
    data_sign = _security_data_sign(data)
    sign_type = str(security_token or "")[:1]
    st = ""
    if sign_type == "0":
        st = hashlib.md5(f"{data_sign}{app_sign}".encode("utf-8")).hexdigest()
    elif sign_type == "1":
        st = hashlib.sha256(f"{data_sign}{app_sign}".encode("utf-8")).hexdigest()
    elif security_token:
        st = hmac.new(str(app_sign).encode("utf-8"), str(data_sign).encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "st": st,
        "ts": str(timestamp),
        "fp": fingerprint,
    }


def get_device_code(openId, device):
    sm2_crypt = sm2.CryptSM2(
        public_key=XYB_SM2_PUBLIC_KEY,
        private_key=None,
        mode=XYB_SM2_MODE,
    )
    return sm2_crypt.encrypt(
            f'b|_{device["brand"]},{device["model"]},{device["system"]},{device["platform"]}aid|_{XYB_APP_ID}t|_{int(time.time() * 1000)}uid|_{rand_str()}oid|_{openId}'.encode()).hex().strip()


def get_header_token(e):
    # 映射列表
    n = list(XYB_KEY)

    # 初始化o列表
    o = [str(i) for i in range(62)]

    # 获取当前时间戳（秒）
    l = int(time.time())

    # 随机打乱o列表并选取前20个元素
    p = random.sample(o, 20)

    # 拼接字符串g
    g = "".join(n[int(e)] for e in p)

    # 排序传入字典e的键
    u = {k: e[k] for k in sorted(e)}

    # 初始化结果字符串d
    d = ""

    # 正则表达式：匹配特殊字符
    special_char_regex = re.compile(r"[`~!@#$%^&*()+=|{}':;',\[\].<>/?~！@#￥%……&*（）——+|{}【】‘；：”“’。，、？]")

    # 遍历u字典，构建d字符串
    for c in u:
        value_text = _normalize_header_token_value(u[c])
        # 如果字段值不包含特殊字符且不在排除字段中
        if c not in XYB_EXCLUDED_KEYS and not special_char_regex.search(value_text):
            d += value_text

    # 拼接最终的字符串
    d = f"{d}{l}{g}"

    # 清理掉不需要的字符
    d = _sanitize_sign_text(d)

    # URL 编码
    d = urllib.parse.quote(d)

    # 计算MD5值
    md5_value = hashlib.md5(d.encode('utf-8')).hexdigest()

    return {
        "m": md5_value,
        "t": str(l),
        "s": "_".join(p) if len(p) > 0 else "",
        "n": XYB_N_HEADER
    }

