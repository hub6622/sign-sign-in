import logging
import os
import tempfile

import requests
from PIL import Image, ImageDraw, ImageFont

from app.config.common import XYB_VERSION, XYB_REFERER, AMAP_WEB_KEY, XYB_N_HEADER
from app.utils.common import get_timestamp
from app.utils.files import get_img_file, clear_session_cache, check_img
from app.utils.params import (
    create_security_fingerprint,
    get_device_code,
    get_header_token,
    get_security_params,
    get_security_url_token,
)

TENCENT_MAP_KEY = "GOZBZ-E4L67-6WLXT-PSLBH-2WEZZ-LOFLE"


def _normalize_address_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple, set)):
        parts = [_normalize_address_text(item) for item in value]
        return " ".join(part for part in parts if part).strip()
    if isinstance(value, dict):
        for key in ("formatted_address", "address", "name", "value"):
            text = _normalize_address_text(value.get(key))
            if text:
                return text
        return str(value).strip()
    return str(value).strip()


def check_session_validity(response_json):
    """
    检查响应是否表示会话已失效
    当响应类似 {'code': '205', 'data': None, 'msg': '未登录', ...} 时返回True
    """
    if isinstance(response_json, dict):
        code = response_json.get('code')
        msg = response_json.get('msg', '')
        if code == '205' or (code == 205) or '未登录' in str(msg):
            return False
    return True


def handle_invalid_session():
    """处理失效的会话：清除缓存并提示"""
    clear_session_cache()
    logging.warning('❌ JSESSIONID已失效，已清除缓存，请重新获取code')


def _normalize_map_provider(provider):
    provider = str(provider or "amap").strip().lower()
    if provider in ("tencent", "qq", "qqmap"):
        return "tencent"
    return "amap"


def _map_key(custom_key, default_key):
    key = str(custom_key or "").strip()
    return key or default_key


def _response_message(data):
    if isinstance(data, dict):
        msg = data.get("msg", data.get("message"))
        if msg is not None and str(msg).strip():
            return str(msg)
    return str(data)


def _is_success_code(code):
    return code == "200" or code == 200


def _assert_session(response_json):
    if not check_session_validity(response_json):
        handle_invalid_session()
        raise RuntimeError('❌ JSESSIONID已失效，请重新获取Code')


def _require_data(response, context):
    try:
        res = response.json()
    except Exception as exc:
        raise RuntimeError(f"{context}: 响应解析失败 {exc}") from exc
    _assert_session(res)
    if response.status_code != 200 or not _is_success_code(res.get("code")) or "data" not in res:
        raise RuntimeError(f"{context}: {_response_message(res)}")
    return res.get("data")


def _require_success(response, context):
    try:
        res = response.json()
    except Exception as exc:
        raise RuntimeError(f"{context}: 响应解析失败 {exc}") from exc
    _assert_session(res)
    if response.status_code != 200 or not _is_success_code(res.get("code")):
        raise RuntimeError(f"{context}: {_response_message(res)}")
    return res


def _security_fingerprint(config):
    if not config.get("securityFingerprint"):
        config["securityFingerprint"] = create_security_fingerprint()
    return config["securityFingerprint"]


def _base_xyb_headers(config):
    return {
        "v": XYB_VERSION,
        "xweb_xhr": "1",
        "content-type": "application/x-www-form-urlencoded",
        "referer": XYB_REFERER,
        "User-Agent": config["userAgent"],
    }


def _fetch_security_token(config, fingerprint, args=None, timeout=5):
    url = "https://xcx.xybsyw.com/common/GetToken.action"
    headers = _base_xyb_headers(config)
    cookies = {"JSESSIONID": args["sessionId"]} if args and args.get("sessionId") else None
    logging.debug(f"准备请求校友邦风控Token: url:{url}, headers:{headers}, data:{{'fp': '***'}}, cookies:{cookies}")
    response = requests.post(url, headers=headers, cookies=cookies, data={"fp": fingerprint}, timeout=timeout)
    logging.debug(f"收到风控Token响应: {response} {response.text}")
    data = _require_data(response, "获取校友邦风控Token失败")
    if not data:
        raise RuntimeError("获取校友邦风控Token失败: data为空")
    return str(data)


def _build_security_context(data, config, args=None):
    fingerprint = _security_fingerprint(config)
    security_token = _fetch_security_token(config, fingerprint, args=args)
    return {
        "params": get_security_params(data, security_token, fingerprint),
        "url_token": get_security_url_token(security_token),
    }


def _form_post(url, data, config, args, include_device_code=False, timeout=5):
    security = _build_security_context(data, config, args=args)
    request_data = {**data, **security["params"]}
    headers = {
        **_base_xyb_headers(config),
        "encryptvalue": args["encryptValue"],
        "n": XYB_N_HEADER,
        "wechat": "1",
    }
    if include_device_code:
        headers["devicecode"] = get_device_code(openId=args.get("openId", ""), device=config["device"])
    cookies = {"JSESSIONID": args["sessionId"]}
    logging.debug(f"准备发起校友邦请求。url:{url}, headers:{headers}, data:{request_data}, cookies:{cookies}")
    response = requests.post(
        url,
        headers=headers,
        cookies=cookies,
        data=request_data,
        params={"t": security["url_token"]},
        timeout=timeout,
    )
    logging.debug(f"收到响应:{response} {response.text}")
    return response


def _is_plan_empty_body(data):
    message = _response_message(data)
    lower = message.lower()
    return (
        ("列表" in message and "空" in message)
        or ("list" in lower and "empty" in lower)
        or "empty list" in lower
    )


def _normalize_tencent_regeo(result):
    address_component = result.get("address_component") or {}
    ad_info = result.get("ad_info") or {}
    formatted_addresses = result.get("formatted_addresses") or {}
    formatted_address = _normalize_address_text(
        formatted_addresses.get("recommend")
        or formatted_addresses.get("rough")
        or result.get("address")
        or formatted_addresses.get("standard_address")
    )
    return {
        "formatted_address": formatted_address,
        "addressComponent": {
            "province": address_component.get("province", ""),
            "city": address_component.get("city") or address_component.get("province", ""),
            "district": address_component.get("district", ""),
            "street": address_component.get("street", ""),
            "streetNumber": address_component.get("street_number", ""),
            "adcode": ad_info.get("adcode", ""),
        },
    }


def _regeo_tencent(userAgent, location, key=None):
    url = "https://apis.map.qq.com/ws/geocoder/v1/"
    headers = {
        "xweb_xhr": "1",
        "Referer": XYB_REFERER,
        "User-Agent": userAgent,
    }
    params = {
        "location": f"{location['latitude']},{location['longitude']}",
        "key": _map_key(key, TENCENT_MAP_KEY),
        "get_poi": "1",
    }
    try:
        logging.debug(f"馃洨锔?鍑嗗鍙戣捣璇锋眰銆倁rl:{url}, headers:{headers}, params:{params}")
        response = requests.get(url, headers=headers, params=params, timeout=5)
        logging.debug(f"馃摗 鏀跺埌鍝嶅簲:{response} {response.text}")
        res = response.json()
        if response.status_code == 200 and res.get("status") == 0 and res.get("result"):
            regeocode = _normalize_tencent_regeo(res["result"])
            if not regeocode["formatted_address"]:
                regeocode["formatted_address"] = f"{location['longitude']},{location['latitude']}"
            logging.info(f"馃搷 瑙ｆ瀽浣嶇疆: {regeocode['formatted_address']}")
            return regeocode
        raise RuntimeError(f"浣嶇疆瑙ｆ瀽澶辫触: {res}")
    except Exception as e:
        logging.error(f"鑵捐鍦板浘鎺ュ彛璇锋眰澶辫触: {e}")
        raise e


def regeo(userAgent, location, provider="amap", map_keys=None):
    map_keys = map_keys if isinstance(map_keys, dict) else {}
    if _normalize_map_provider(provider) == "tencent":
        return _regeo_tencent(userAgent, location, map_keys.get("tencent"))

    logging.info('正在调用高德地图解析经纬度...')
    url = "https://restapi.amap.com/v3/geocode/regeo"
    headers = {
        "xweb_xhr": "1", "Content-Type": "application/json",
        "Referer": XYB_REFERER,
        "User-Agent": userAgent,
    }
    amap_key = _map_key(map_keys.get("amap"), AMAP_WEB_KEY)
    params = {
        "s": "rsx", "platform": "WXJS", "logversion": "2.0", "extensions": "all",
        "sdkversion": "1.2.0", "key": amap_key,
        "appname": amap_key,
        "location": f"{location['longitude']},{location['latitude']}",
    }
    try:
        logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, params:{params}")
        response = requests.get(url, headers=headers, params=params, timeout=5)
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()
        if 'regeocode' in res:
            regeocode = dict(res['regeocode'] or {})
            formatted_address = _normalize_address_text(regeocode.get('formatted_address'))
            if not formatted_address:
                formatted_address = f"{location['longitude']},{location['latitude']}"
            regeocode['formatted_address'] = formatted_address
            logging.info(f"📍 解析位置: {formatted_address}")
            return regeocode
        else:
            raise RuntimeError(f"位置解析失败: {res}")
    except Exception as e:
        logging.error(f"高德接口请求失败: {e}")
        raise e


def get_plan(userAgent, args, config=None):
    logging.info('正在获取实习计划...')
    url = "https://xcx.xybsyw.com/student/clock/GetPlan.action"
    data = {}
    config = config if isinstance(config, dict) else {"userAgent": userAgent}

    try:
        response = _form_post(url, data, config=config, args=args, include_device_code=False, timeout=5)
        res = response.json()
        _assert_session(res)
        if _is_plan_empty_body(res):
            return []
        if 'data' in res and res['data']:
            return res['data']
        raise RuntimeError(f"获取计划失败: {res.get('msg', 'Unknown error')}")
    except Exception as e:
        raise RuntimeError(f"计划接口请求异常: {e}")


def get_default_plan(userAgent, args, config=None):
    logging.info('正在获取默认实习计划...')
    url = "https://xcx.xybsyw.com/student/clock/GetPlan!getDefault.action"
    data = {}
    config = config if isinstance(config, dict) else {"userAgent": userAgent}

    try:
        response = _form_post(url, data, config=config, args=args, include_device_code=False, timeout=5)
        res = response.json()
        _assert_session(res)
        if _is_plan_empty_body(res):
            return {}
        return _require_data(response, "获取默认实习计划失败") or {}
    except Exception as e:
        raise RuntimeError(f"默认计划接口请求异常: {e}")


def get_open_id(config, code):
    logging.info("正在获取open_id...")
    url = "https://xcx.xybsyw.com/common/getOpenId.action"
    data = {"code": code}

    try:
        security = _build_security_context(data, config)
        headers = {
            **_base_xyb_headers(config),
            "devicecode": get_device_code("", config['device']),
        }
        request_data = {**data, **security["params"]}
        logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{request_data}")
        response = requests.post(
            url=url,
            headers=headers,
            data=request_data,
            params={"t": security["url_token"]},
            allow_redirects=False,
            timeout=5,
        )
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()
        if res.get('code') == '202':
            raise RuntimeError(f'code已失效，请重启小程序。接口响应：{res}')
        return _require_data(response, "获取OpenID失败")
    except Exception as e:
        raise RuntimeError(f"获取OpenID失败: {e}")


def wx_login(config, openIdData):
    logging.info("正在进行微信登录...")
    data = {
        "openId": openIdData['openId'],
        "unionId": openIdData['unionId']
    }
    url = "https://xcx.xybsyw.com/login/login!wx.action"
    try:
        response = _form_post(
            url,
            data,
            config=config,
            args=openIdData,
            include_device_code=True,
            timeout=5,
        )
        logging.debug(f"📡 收到响应:{response} {response.text}")
        return _require_data(response, "登录失败")
    except Exception as e:
        raise RuntimeError(f"登录失败: {e}")


def login(config, use_cache=True):
    """
    登录函数，支持JSESSIONID缓存
    :param config: 配置信息
    :param use_cache: 是否使用缓存，如果为True且缓存有效则直接返回缓存
    :return: 登录结果字典
    """
    from app.utils.files import get_valid_session_cache, save_session_cache

    # 尝试使用缓存
    if use_cache:
        cached = get_valid_session_cache()
        if cached:
            logging.info('✅ 使用缓存的JSESSIONID')
            return {
                'openId': cached['openId'],
                'unionId': cached['unionId'],
                'encryptValue': cached['encryptValue'],
                'sessionId': cached['sessionId'],
                'traineeId': cached.get('traineeId')
            }

    code = config.get('code')
    if not code or code == '':
        raise RuntimeError('❌ Code为空，请重新获取！')

    ### 获取open_id、union_id等信息
    openIdData = get_open_id(config=config, code=code)

    ### 获取登录参数encryptValue、sessionId
    login_data = wx_login(config=config, openIdData=openIdData)

    result = {
        'openId': openIdData['openId'],
        'unionId': openIdData['unionId'],
        'encryptValue': login_data['encryptValue'],
        'sessionId': login_data['sessionId'],
    }

    # 保存到缓存
    save_session_cache(
        session_id=result['sessionId'],
        encrypt_value=result['encryptValue'],
        open_id=result['openId'],
        union_id=result['unionId'],
        trainee_id=result.get('traineeId')
    )
    logging.info('✅ 登录成功，已缓存JSESSIONID')

    return result


# ------------------------------拍照签到----------------------------------------


def photo_sign_in_or_out(args, config, geo, traineeId, opt):
    logging.info('正在执行拍照签到流程...')

    watermark = watermark_info(args=args, config=config, traineeId=traineeId)
    watermarked_path = render_watermarked_photo(opt.get('image_path'), watermark, geo.get('formatted_address', ''))
    policyData = commonPostPolicy(args=args, config=config)
    timestamp = get_timestamp()
    files = get_img_file(timestamp, watermarked_path)
    try:
        ossData = aliyun_OSS(files=files, timestamp=timestamp, policyData=policyData,config=config)
        post_new(args=args, config=config, traineeId=traineeId, geo=geo, imgUrl=ossData['key'], opt=opt)
        # deliver_value(args=args, config=config, traineeId=traineeId)
    finally:
        file_obj = files.get("file", [None, None, None])[1]
        if file_obj:
            file_obj.close()
        try:
            os.remove(watermarked_path)
        except OSError:
            pass


def watermark_info(args, config, traineeId):
    url = "https://xcx.xybsyw.com/student/clock/postNew!watermarkInfo.action"

    data = {
        "traineeId": str(traineeId)
    }

    response = _form_post(url, data, config=config, args=args, include_device_code=False, timeout=5)
    logging.info(f"{response} {response.text}")
    return _require_data(response, "获取拍照打卡水印信息失败")


def _load_watermark_font(size):
    candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                pass
    return ImageFont.load_default()


def render_watermarked_photo(image_path, watermark, address):
    source_path = check_img(image_path)
    with Image.open(source_path) as image:
        image = image.convert("RGB")
        width, height = image.size
        scale = min(3000 / width, 3000 / height, 1)
        if scale < 1:
            image = image.resize((max(1, int(width * scale)), max(1, int(height * scale))), Image.LANCZOS)

        draw = ImageDraw.Draw(image)
        draw.text((100, 70), str(watermark.get("time", "")), fill=(255, 255, 255), font=_load_watermark_font(48))
        draw.text((280, 70), str(watermark.get("today", "")), fill=(255, 255, 255), font=_load_watermark_font(32))
        draw.text((100, 120), str(address or ""), fill=(255, 255, 255), font=_load_watermark_font(28))
        draw.text((100, 155), str(watermark.get("info", "")), fill=(255, 255, 255), font=_load_watermark_font(28))

        out_width = max(1, int(image.size[0] * 0.8))
        out_height = max(1, int(image.size[1] * 0.8))
        image = image.resize((out_width, out_height), Image.LANCZOS)
        fd, out_path = tempfile.mkstemp(prefix="xyb-watermark-", suffix=".jpg")
        os.close(fd)
        image.save(out_path, format="JPEG", quality=80)
        return out_path


def commonPostPolicy(args, config):
    logging.info('正在获取上传凭证...')
    url = "https://xcx.xybsyw.com/uploadfile/commonPostPolicy.action"

    data = {
        "customerType": "STUDENT",
        "uploadType": "UPLOAD_STUDENT_CLOCK_IMGAGES",
        "publicRead": "true"
    }

    response = _form_post(url, data, config=config, args=args, include_device_code=True, timeout=5)
    logging.info(f"{response} {response.text}")
    return _require_data(response, "commonPostPolicy请求异常")


def aliyun_OSS(files, timestamp, policyData,config):
    logging.info('正在上传至阿里云OSS...')

    url = policyData['host']

    headers = {
        "Referer": XYB_REFERER,
        "User-Agent": config['userAgent'],
    }

    key = f"{policyData['dir']}/{timestamp}.jpg"
    logging.info(f"key: {key}")

    data = {
        "key": key,
        "policy": policyData['policy'],
        "OSSAccessKeyId": policyData['accessid'],
        "signature": policyData['signature'],
        "success_action_status": "200",
        "customerType": policyData['customParams']['x:customer_type_key'],
        "uploadType": policyData['customParams']['x:upload_type_key'],
        "callback": policyData['callback'],
    }

    logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{data}, files:{files}")
    response = requests.post(url, data=data, files=files, headers=headers)
    logging.debug(f"📡 收到响应:{response} {response.text}")

    if response.status_code != 200:
        raise RuntimeError(f"aliyun_OSS请求异常, {response} {response.text}")

    res = response.json()
    return res['vo']


def post_new(args, config, traineeId, geo, imgUrl, opt):
    url = "https://xcx.xybsyw.com/student/clock/PostNew.action"

    data = {
        "traineeId": str(traineeId),
        "adcode": geo['addressComponent']['adcode'],
        "lat": config['location']['latitude'],
        "lng": config['location']['longitude'],
        "address": geo['formatted_address'],
        "deviceName": config['device']['model'],
        # "punchInStatus": "1",
        "punchInStatus": "0",
        # 2：普通签到，1：普通签退
        # "clockStatus": "2",
        "clockStatus": str(opt['code']),
        # "imgUrl": "temp/20251119/school/14422/xcx/student/clock/11621617/1763557557282.jpg",
        "imgUrl": imgUrl,
        "reason": "",
        "addressId": "null"
    }

    response = _form_post(url, data, config=config, args=args, include_device_code=True, timeout=5)
    _require_success(response, "post_new请求异常")


def deliver_value(args, config, traineeId):
    url = "https://xcx.xybsyw.com/student/DeliverValue!post.action"

    data = {
        "traineeId": str(traineeId)
    }

    header_token = get_header_token(data)
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "encryptvalue": args['encryptValue'],
        "m": header_token['m'],
        "n": header_token['n'],
        "referer": XYB_REFERER,
        "s": header_token['s'],
        "t": header_token['t'],
        "user-agent": config['userAgent'],
        "v": XYB_VERSION,
        "wechat": "1",
        "xweb_xhr": "1"
    }
    cookies = {"JSESSIONID": args['sessionId']}

    logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{data}, cookies:{cookies}")
    response = requests.post(url, headers=headers, cookies=cookies, data=data)
    logging.debug(f"📡 收到响应:{response} {response.text}")

    res = response.json()
    if response.status_code != 200 or res['code'] != "200":
        raise RuntimeError(f"deliver_value请求异常, {response} {response.text}")


def simple_sign_in_or_out(args, geo, traineeId, config, opt):
    logging.info(f'正在调用接口进行: {opt["action"]}...')
    url = "https://xcx.xybsyw.com/student/clock/Post.action"
    device = config['device']
    data = {'punchInStatus': "0",  # 2：普通签到，1：普通签退
            'clockStatus': str(opt['code']), 'traineeId': str(traineeId),
            'adcode': geo['addressComponent']['adcode'],
            'model': device['model'], 'brand': device['brand'], 'platform': device['platform'],
            'system': device['system'], 'openId': args['openId'], 'unionId': args['unionId'],
            'lng': config['location']['longitude'], 'lat': config['location']['latitude'],
            'address': geo['formatted_address'], 'deviceName': device['model'], }

    try:
        response = _form_post(url, data, config=config, args=args, include_device_code=True, timeout=5)
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()

        _assert_session(res)

        msg = res['msg']
        code = res['code']

        info = ''

        if code == "200":
            if msg == 'success':
                info = f'✅ {opt["action"]}成功！'
                logging.info(info)
            elif msg == '已经签到':
                info = f'✅ 已经{opt["action"]}过了。'
                logging.info(info)
        elif code == "403":
            logging.warning(f'⚠️ {msg}')
        elif code == "202":
            raise RuntimeError(f"配置错误，请检查device和userAgent参数 (Code 202): {msg}")
        else:
            raise RuntimeError(f'操作失败: {msg}')

        return info
    except Exception as e:
        raise RuntimeError(f"签到请求异常: {e}")


# ------------------------------周记相关接口----------------------------------------


def load_blog_year(args, config):
    """加载周记年份和月份"""
    logging.info('正在加载周记年份和月份...')
    url = "https://xcx.xybsyw.com/student/blog/LoadBlogDate!weekYear.action"

    data = {
        "traineeId": str(args.get('traineeId', ''))
    }

    header_token = get_header_token(data)
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "encryptvalue": args['encryptValue'],
        "m": header_token['m'],
        "n": header_token['n'],
        "referer": XYB_REFERER,
        "s": header_token['s'],
        "t": header_token['t'],
        "user-agent": config['userAgent'],
        "v": XYB_VERSION,
        "wechat": "1",
        "xweb_xhr": "1"
    }
    cookies = {
        "JSESSIONID": args['sessionId']
    }

    try:
        logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{data}, cookies:{cookies}")
        response = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=10)
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()

        if not check_session_validity(res):
            handle_invalid_session()
            raise RuntimeError('❌ JSESSIONID已失效，请重新获取code')

        logging.info(f"加载周记年份和月份：{res.get('data', 'Unknown error')}")
        if res.get('code') == '200' and 'data' in res:
            return res['data']
        else:
            raise RuntimeError(f"加载年份月份失败: {res.get('msg', 'Unknown error')}")
    except Exception as e:
        raise RuntimeError(f"加载年份月份请求异常: {e}")


def load_blog_date(args, config, year, month):
    """加载指定年月下的周信息"""
    logging.info(f'正在加载{year}年{month}月的周信息...')
    url = "https://xcx.xybsyw.com/student/blog/LoadBlogDate!week.action"

    data = {
        "year": str(year),
        "month": str(month),
        "traineeId": str(args.get('traineeId', '')),
        "id": ""
    }

    header_token = get_header_token(data)
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "encryptvalue": args['encryptValue'],
        "m": header_token['m'],
        "n": header_token['n'],
        "referer": XYB_REFERER,
        "s": header_token['s'],
        "t": header_token['t'],
        "user-agent": config['userAgent'],
        "v": XYB_VERSION,
        "wechat": "1",
        "xweb_xhr": "1"
    }
    cookies = {
        "JSESSIONID": args['sessionId']
    }

    try:
        logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{data}, cookies:{cookies}")
        response = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=10)
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()

        if not check_session_validity(res):
            handle_invalid_session()
            raise RuntimeError('❌ JSESSIONID已失效，请重新获取code')

        logging.info(f"加载周信息：{res.get('msg', 'Unknown error')}")
        if res.get('code') == '200' and 'data' in res:
            return res['data']
        else:
            raise RuntimeError(f"加载周信息失败: {res.get('msg', 'Unknown error')}")
    except Exception as e:
        raise RuntimeError(f"加载周信息请求异常: {e}")


def submit_blog(args, config, blog_title, blog_body, start_date, end_date, blog_open_type, trainee_id):
    """提交周记"""
    logging.info('正在提交周记...')
    url = "https://xcx.xybsyw.com/student/blog/Blog!save.action"

    data = {
        "blogType": "1",
        "blogTitle": blog_title,
        "blogBody": blog_body,
        "blogOpenType": str(blog_open_type),  # 查看权限：1-公开，2-仅自己
        "traineeId": str(trainee_id),
        "isDraft": "0",
        "startDate": start_date,
        "endDate": end_date,
        "backgroundTemplateId": "0",
        "fileJson": "[{\"fileName\":\"\"}]",
        "blogId": "undefined"
    }

    header_token = get_header_token(data)
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "devicecode": get_device_code(openId=args['openId'], device=config['device']),
        "encryptvalue": args['encryptValue'],
        "m": header_token['m'],
        "n": header_token['n'],
        "referer": XYB_REFERER,
        "s": header_token['s'],
        "t": header_token['t'],
        "user-agent": config['userAgent'],
        "v": XYB_VERSION,
        "wechat": "1",
        "xweb_xhr": "1"
    }
    cookies = {
        "JSESSIONID": args['sessionId']
    }

    try:
        logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{data}, cookies:{cookies}")
        response = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=10)
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()

        if not check_session_validity(res):
            handle_invalid_session()
            raise RuntimeError('❌ JSESSIONID已失效，请重新获取code')

        logging.info(f"提交周记结果: {res}")
        if res.get('code') == '200':
            logging.info(f"提交周记成功: {res.get('msg', 'Unknown error')}")
            return res.get('data')
        else:
            raise RuntimeError(f"提交周记失败: {res.get('msg', 'Unknown error')}")
    except Exception as e:
        raise RuntimeError(f"提交周记请求异常: {e}")


def xyb_completion(args, config, prompt, on_delta=None):
    """
    调用 AI 完成接口
    :param args: 登录参数
    :param config: 配置
    :param prompt: 提示词
    :param on_delta: 流式输出回调函数，接收每个文本片段
    :return: 完整的生成内容
    """
    data = {
        "processType": "0",
        "content": prompt,
        "questionType": "0",
        "type": "0",
        "aiSessionMsgType": "4"
    }
    header_token = get_header_token(data)
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "devicecode": get_device_code(openId=args['openId'], device=config['device']),
        "encryptvalue": args['encryptValue'],
        "m": header_token['m'],
        "n": header_token['n'],
        "referer": XYB_REFERER,
        "s": header_token['s'],
        "t": header_token['t'],
        "user-agent": config['userAgent'],
        "v": XYB_VERSION,
        "wechat": "1",
        "xweb_xhr": "1"
    }
    cookies = {
        "JSESSIONID": args['sessionId']
    }
    url = "https://xcx.xybsyw.com/careerplanning/saveSession.action"

    try:
        import json
        response = requests.post(url, data=data, headers=headers, cookies=cookies, timeout=60)
        res = response.json()

        if res.get('code') == '200' and 'data' in res:
            content = res['data'].get('content', '')
            if on_delta and content:
                # 模拟流式输出效果
                for char in content:
                    on_delta(char)
            return content
        else:
            raise RuntimeError(f"AI生成失败: {res.get('msg', 'Unknown error')}")
    except json.JSONDecodeError as e:
        logging.error(f"AI响应解析失败: {e}")
        raise RuntimeError(f"AI响应解析失败: {e}")
    except Exception as e:
        logging.error(f"AI生成请求异常: {e}")
        raise RuntimeError(f"AI生成请求异常: {e}")


def blog_list(args, config, page, blogType="1"):
    logging.info(f'正在加载第{page}页周记列表...')
    data = {
        "blogType": blogType,
        "planId": "",
        "reviewStatus": "null",
        "page": str(page)
    }
    header_token = get_header_token(data)
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "devicecode": get_device_code(openId=args['openId'], device=config['device']),
        "encryptvalue": args['encryptValue'],
        "m": header_token['m'],
        "n": header_token['n'],
        "referer": XYB_REFERER,
        "s": header_token['s'],
        "t": header_token['t'],
        "user-agent": config['userAgent'],
        "v": XYB_VERSION,
        "wechat": "1",
        "xweb_xhr": "1"
    }
    cookies = {
        "JSESSIONID": args['sessionId']
    }
    url = "https://xcx.xybsyw.com/student/blog/BlogList.action"

    try:
        logging.debug(f"🛩️ 准备发起请求。url:{url}, headers:{headers}, data:{data}, cookies:{cookies}")
        response = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=10)
        logging.debug(f"📡 收到响应:{response} {response.text}")
        res = response.json()

        if not check_session_validity(res):
            handle_invalid_session()
            raise RuntimeError('❌ JSESSIONID已失效，请重新获取code')

        if res.get('code') == '200' and 'data' in res:
            return res['data']
        else:
            raise RuntimeError(f"获取周记列表失败: {res.get('msg', 'Unknown error')}")
    except Exception as e:
        raise RuntimeError(f"获取周记列表请求异常: {e}")
