# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import requests
import json
import time
import random
import re
from threading import Thread, Lock
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Lưu trữ session người dùng (server side)
user_sessions = {}
running_jobs = {}
job_stats = {}
log_lock = Lock()

#====================================================
# HÀM CHUYỂN ĐỔI ĐỊNH DẠNG PROXY
#====================================================
def parse_proxy(proxy_input):
    if not proxy_input or proxy_input.lower() == 'skip':
        return None
    if proxy_input.count(':') == 3 and not proxy_input.startswith('http'):
        parts = proxy_input.split(':')
        if len(parts) == 4:
            host, port, username, password = parts
            return f"http://{username}:{password}@{host}:{port}"
    if proxy_input.startswith('http'):
        return proxy_input
    if ':' in proxy_input and not proxy_input.startswith('http'):
        return f"http://{proxy_input}"
    return None

#====================================================
# TÁCH USER-AGENT TỪ COOKIE
#====================================================
def parse_cookie_line(cookie_line):
    if '|' in cookie_line:
        parts = cookie_line.split('|', 1)
        cookie = parts[0].strip()
        ua = parts[1].strip() if len(parts) > 1 else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        return cookie, ua
    return cookie_line.strip(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

#====================================================
# KIỂM TRA COOKIE VÀ LẤY USERNAME
#====================================================
def check_and_get_username(cookie, user_agent, proxy=None):
    try:
        headers = {
            "Cookie": cookie,
            "User-Agent": user_agent,
        }
        proxies = {'http': proxy, 'https': proxy} if proxy else None

        # Thử lấy bằng API trước
        token = None
        for part in cookie.split(';'):
            if 'csrftoken=' in part:
                token = part.strip().split('=')[1]
                break
        
        if token:
            api_headers = {
                "Cookie": cookie,
                "User-Agent": user_agent,
                "X-CSRFToken": token,
                "X-IG-App-ID": "936619743392459",
            }
            api_url = "https://www.instagram.com/api/v1/accounts/current_user/?edit=true"
            api_resp = requests.get(api_url, headers=api_headers, proxies=proxies, timeout=10)
            
            if api_resp.status_code == 200:
                try:
                    data = api_resp.json()
                    if data.get('status') == 'ok' and data.get('user'):
                        username = data['user'].get('username')
                        return True, username
                except:
                    pass

        # Fallback: lấy từ web
        r = requests.get("https://www.instagram.com/accounts/edit/", 
                        headers=headers, proxies=proxies, timeout=15)

        # Tìm username trong HTML
        patterns = [
            r'"username":"([^"]+)"',
            r'"username"\s*:\s*"([^"]+)"',
        ]
        
        for pattern in patterns:
            m = re.search(pattern, r.text)
            if m:
                username = m.group(1)
                return True, username

        return False, None
        
    except Exception as e:
        return False, None

#====================================================
# FOLLOW EVANS
#====================================================
def follow_evans(cookie: str, user_agent: str, proxy: str = None) -> bool:
    try:
        cookies_str = cookie
        token = None
        for part in cookies_str.split(';'):
            if 'csrftoken=' in part:
                token = part.strip().split('=')[1]
                break

        if not token:
            return False

        evans_id = "44376707012"
        headers = {
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': cookies_str,
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'user-agent': user_agent,
            'x-csrftoken': token,
            'x-ig-app-id': '936619743392459',
        }

        data = {'user_id': evans_id}
        url = f"https://www.instagram.com/api/v1/friendships/create/{evans_id}/"
        proxies = {'http': proxy, 'https': proxy} if proxy else None

        resp = requests.post(url, headers=headers, data=data, timeout=10, proxies=proxies)

        if resp.status_code == 200:
            result = resp.json()
            is_ok = result.get("status") == "ok"
            friendship = result.get("friendship_status", {})
            is_already_following = friendship.get("following") is True
            return is_ok or is_already_following

        return False
    except Exception as e:
        return False

#====================================================
# FOLLOW TARGET
#====================================================
def follow_target_job(cookie: str, user_agent: str, target_id: str, proxy: str = None) -> bool:
    try:
        cookies_str = cookie
        token = None
        for part in cookies_str.split(';'):
            if 'csrftoken=' in part:
                token = part.strip().split('=')[1]
                break

        if not token:
            return False

        headers = {
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': cookies_str,
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'user-agent': user_agent,
            'x-csrftoken': token,
            'x-ig-app-id': '936619743392459',
        }

        data = {'user_id': target_id}
        url = f"https://www.instagram.com/api/v1/friendships/create/{target_id}/"
        proxies = {'http': proxy, 'https': proxy} if proxy else None

        resp = requests.post(url, headers=headers, data=data, timeout=10, proxies=proxies)

        if resp.status_code == 200:
            result = resp.json()
            return result.get("status") == "ok"
        return False
    except Exception as e:
        return False

#====================================================
# LIKE JOB
#====================================================
def like_post(cookie: str, user_agent: str, post_url: str, proxy: str = None) -> bool:
    try:
        m = re.search(r"/p/([^/]+)/", post_url)
        if not m:
            return False
        shortcode = m.group(1)

        token = None
        for p in cookie.split(";"):
            if "csrftoken=" in p:
                token = p.strip().split("=")[1]
                break

        if not token:
            return False

        headers = {
            "Cookie": cookie,
            "User-Agent": user_agent,
            "X-CSRFToken": token,
            "X-IG-App-ID": "936619743392459",
            "Referer": post_url,
        }

        proxies = {'http': proxy, 'https': proxy} if proxy else None

        # Lấy media_id từ shortcode
        info_url = f"https://www.instagram.com/p/{shortcode}/?__a=1&__d=dis"
        info_resp = requests.get(info_url, headers=headers, timeout=10, proxies=proxies)

        if info_resp.status_code != 200:
            return False

        info = info_resp.json()
        media_id = None

        try:
            if "items" in info and len(info["items"]) > 0:
                media_id = info["items"][0]["id"]
            elif "graphql" in info and "shortcode_media" in info["graphql"]:
                media_id = info["graphql"]["shortcode_media"]["id"]
            elif "id" in info:
                media_id = info["id"]
        except:
            return False

        if not media_id:
            return False

        # Like post
        like_url = f"https://www.instagram.com/api/v1/media/{media_id}/like/"
        like_headers = headers.copy()
        like_headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://www.instagram.com',
        })

        r = requests.post(like_url, headers=like_headers, timeout=10, proxies=proxies)
        
        if r.status_code == 200:
            try:
                result = r.json()
                return result.get("status") == "ok"
            except:
                return True if '"status":"ok"' in r.text else False
        return False
    except Exception as e:
        return False

#====================================================
# GOLIKE MANAGER
#====================================================
class GolikeManager:
    def __init__(self, auth_token, t_value):
        self.headers = {
            "Authorization": ("Bearer " + auth_token) if not auth_token.startswith("Bearer ") else auth_token,
            "T": t_value,
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json"
        }
        self.auth_token = auth_token
        self.t_value = t_value

    def get_user_info(self):
        try:
            return requests.get("https://gateway.golike.net/api/users/me", headers=self.headers).json()
        except:
            return None

    def add_account(self, username):
        try:
            url = "https://gateway.golike.net/api/instagram-account/verify-account"
            data = {"object_id": username}
            return requests.post(url, headers=self.headers, json=data).json()
        except Exception as e:
            return {"success": False, "message": "Lỗi kết nối API Golike."}

    def get_accounts(self):
        try:
            return requests.get("https://gateway.golike.net/api/instagram-account", headers=self.headers).json()
        except:
            return None

    def get_job(self, acc_id):
        try:
            return requests.get(
                f"https://gateway.golike.net/api/advertising/publishers/instagram/jobs?instagram_account_id={acc_id}",
                headers=self.headers
            ).json()
        except:
            return None

    def complete_job(self, acc_id, job_id):
        try:
            url = "https://gateway.golike.net/api/advertising/publishers/instagram/complete-jobs"
            data = {
                "instagram_account_id": acc_id,
                "instagram_users_advertising_id": job_id,
                "async": True
            }
            return requests.post(url, headers=self.headers, json=data).json()
        except:
            return None

    def skip_job(self, acc_id, job):
        try:
            url = "https://gateway.golike.net/api/advertising/publishers/instagram/skip-jobs"
            data = {
                "ads_id": job["id"],
                "account_id": acc_id,
                "object_id": job["object_id"],
                "type": job["type"],
                "async": True
            }
            return requests.post(url, headers=self.headers, json=data)
        except:
            return None

#====================================================
# CHẠY JOB CHO 1 TÀI KHOẢN
#====================================================
def run_account_job(session_id, account_index, gm, base_delay):
    ses = user_sessions[session_id]
    account = ses['accounts'][account_index]
    
    cookie = account['cookie']
    user_agent = account['user_agent']
    proxy = account.get('proxy')
    username = account['username']
    
    # Setup account ID trên Golike
    try:
        accs = gm.get_accounts()
        accounts_data = []
        if accs and accs.get("status") == 200:
            if "data" in accs:
                accounts_data = accs["data"]
            elif "accounts" in accs:
                accounts_data = accs["accounts"]
        
        acc_id = None
        for acc in accounts_data:
            acc_username = acc.get("instagram_username") or acc.get("username")
            if acc_username and acc_username.lower() == username.lower():
                acc_id = acc.get("id")
                break
        
        if not acc_id:
            # Thêm tài khoản mới
            add = gm.add_account(username)
            if add and add.get("success"):
                time.sleep(2)
                accs_new = gm.get_accounts()
                if accs_new and accs_new.get("status") == 200:
                    accounts_data_new = accs_new.get("data") or accs_new.get("accounts") or []
                    for acc in accounts_data_new:
                        acc_username = acc.get("instagram_username") or acc.get("username")
                        if acc_username and acc_username.lower() == username.lower():
                            acc_id = acc.get("id")
                            break
        
        if not acc_id:
            account['status'] = 'error'
            return
        
        account['acc_id'] = acc_id
    except Exception as e:
        account['status'] = 'error'
        return
    
    last_check = 0
    last_log = ""
    
    while running_jobs.get(session_id, False):
        try:
            # Check cookie mỗi 20 job (giảm tần suất check)
            if last_check >= 20:
                alive, new_username = check_and_get_username(cookie, user_agent, proxy)
                if not alive:
                    account['status'] = 'die'
                    with log_lock:
                        ses['last_log'] = f"[{username}] ❌ Cookie đã hết hạn"
                    break
                last_check = 0
            
            # Đếm ngược delay - chỉ log khi số thay đổi
            for i in range(base_delay, 0, -1):
                if not running_jobs.get(session_id, False):
                    break
                current_log = f"[{username}] ⏳ Chờ {i} giây"
                if current_log != last_log:
                    with log_lock:
                        ses['last_log'] = current_log
                    last_log = current_log
                time.sleep(1)
            
            if not running_jobs.get(session_id, False):
                break
            
            current_log = f"[{username}] 🔍 Đang tìm job..."
            if current_log != last_log:
                with log_lock:
                    ses['last_log'] = current_log
                last_log = current_log
            
            job = gm.get_job(acc_id)
            if not job or not job.get("data"):
                current_log = f"[{username}] ⚠️ Không có job, chờ 5 giây..."
                if current_log != last_log:
                    with log_lock:
                        ses['last_log'] = current_log
                    last_log = current_log
                time.sleep(5)
                continue

            info = job["data"]
            job_type = info["type"]
            job_id = info["id"]
            
            if job_type == "follow":
                current_log = f"[{username}] 🔄 Đang follow..."
            else:
                current_log = f"[{username}] ❤️ Đang like..."
                
            if current_log != last_log:
                with log_lock:
                    ses['last_log'] = current_log
                last_log = current_log
            
            job_success = False
            money = 0

            if job_type == "follow":
                target = info["object_id"]
                ok = follow_target_job(cookie, user_agent, target, proxy)
                if ok:
                    current_log = f"[{username}] 💰 Đang nhận xu..."
                    with log_lock:
                        ses['last_log'] = current_log
                    complete = gm.complete_job(acc_id, job_id)
                    if complete and complete.get("success"):
                        money = complete.get("data", {}).get("prices", 0)
                        account['stats']['money'] += money
                        account['stats']['success'] += 1
                        job_success = True
                        current_log = f"[{username}] ✅ Hoàn thành +{money} xu"
                        with log_lock:
                            ses['last_log'] = current_log
                        last_log = current_log
                    else:
                        account['stats']['fail'] += 1
                        current_log = f"[{username}] ❌ Lỗi nhận xu"
                        with log_lock:
                            ses['last_log'] = current_log
                        last_log = current_log
                else:
                    account['stats']['fail'] += 1
                    current_log = f"[{username}] ❌ Follow thất bại"
                    with log_lock:
                        ses['last_log'] = current_log
                    last_log = current_log

            elif job_type == "like":
                link = info.get("link", "")
                ok = like_post(cookie, user_agent, link, proxy)
                if ok:
                    current_log = f"[{username}] 💰 Đang nhận xu..."
                    with log_lock:
                        ses['last_log'] = current_log
                    complete = gm.complete_job(acc_id, job_id)
                    if complete and complete.get("success"):
                        money = complete.get("data", {}).get("prices", 0)
                        account['stats']['money'] += money
                        account['stats']['success'] += 1
                        job_success = True
                        current_log = f"[{username}] ✅ Hoàn thành +{money} xu"
                        with log_lock:
                            ses['last_log'] = current_log
                        last_log = current_log
                    else:
                        account['stats']['fail'] += 1
                        current_log = f"[{username}] ❌ Lỗi nhận xu"
                        with log_lock:
                            ses['last_log'] = current_log
                        last_log = current_log
                else:
                    account['stats']['fail'] += 1
                    current_log = f"[{username}] ❌ Like thất bại"
                    with log_lock:
                        ses['last_log'] = current_log
                    last_log = current_log

            if not job_success:
                try:
                    gm.skip_job(acc_id, info)
                except:
                    pass

            last_check += 1
            time.sleep(2)

        except Exception as e:
            current_log = f"[{username}] ❌ Lỗi: {str(e)[:30]}"
            if current_log != last_log:
                with log_lock:
                    ses['last_log'] = current_log
                last_log = current_log
            time.sleep(5)
    
    account['status'] = 'stopped'

#====================================================
# CHẠY JOB CHO NHIỀU TÀI KHOẢN
#====================================================
def run_unlimited_jobs(session_id, base_delay):
    running_jobs[session_id] = True
    ses = user_sessions[session_id]
    gm = ses["golike"]
    
    # Reset status cho tất cả accounts
    for acc in ses['accounts']:
        acc['status'] = 'active'
    
    # Tạo thread cho mỗi account
    threads = []
    for i in range(len(ses['accounts'])):
        thread = Thread(target=run_account_job, args=(session_id, i, gm, base_delay))
        thread.daemon = True
        thread.start()
        threads.append(thread)
        time.sleep(1.5)  # Giảm delay giữa các account
    
    # Đợi các thread kết thúc
    for thread in threads:
        thread.join()
    
    running_jobs[session_id] = False

#====================================================
# ROUTES
#====================================================

@app.route('/')
def index():
    return HTML_TEMPLATE

@app.route('/api/new-session', methods=['POST'])
def new_session():
    data = request.json
    session_id = data.get('session_id')
    
    if session_id and session_id in user_sessions:
        ses = user_sessions[session_id]
        return jsonify({
            'success': True,
            'session_id': session_id,
            'has_golike': 'golike' in ses,
            'golike_token': ses.get('golike_token', ''),
            'golike_t': ses.get('golike_t', ''),
            'accounts': ses.get('accounts', []),
            'is_running': running_jobs.get(session_id, False),
            'last_log': ses.get('last_log', ''),
            'delay': ses.get('delay', 5)
        })
    else:
        new_id = str(uuid.uuid4())
        user_sessions[new_id] = {'accounts': [], 'delay': 5}
        return jsonify({
            'success': True,
            'session_id': new_id,
            'has_golike': False,
            'golike_token': '',
            'golike_t': '',
            'accounts': [],
            'is_running': False,
            'last_log': '',
            'delay': 5
        })

@app.route('/api/get-status', methods=['POST'])
def get_status():
    data = request.json
    session_id = data.get('session_id')
    
    if session_id not in user_sessions:
        return jsonify({'success': False})
    
    ses = user_sessions[session_id]
    
    total_stats = {'success': 0, 'fail': 0, 'money': 0}
    accounts_info = []
    
    for acc in ses.get('accounts', []):
        total_stats['success'] += acc.get('stats', {}).get('success', 0)
        total_stats['fail'] += acc.get('stats', {}).get('fail', 0)
        total_stats['money'] += acc.get('stats', {}).get('money', 0)
        accounts_info.append({
            'username': acc['username'],
            'status': acc.get('status', 'active'),
            'stats': acc.get('stats', {'success': 0, 'fail': 0, 'money': 0})
        })
    
    return jsonify({
        'success': True,
        'has_golike': 'golike' in ses,
        'golike_token': ses.get('golike_token', ''),
        'golike_t': ses.get('golike_t', ''),
        'accounts': accounts_info,
        'total_stats': total_stats,
        'is_running': running_jobs.get(session_id, False),
        'last_log': ses.get('last_log', ''),
        'delay': ses.get('delay', 5)
    })

@app.route('/api/configure-golike', methods=['POST'])
def configure_golike():
    data = request.json
    session_id = data.get('session_id')
    auth_line = data.get('auth_line', '')
    
    if not session_id or not auth_line:
        return jsonify({'success': False, 'message': 'Thiếu thông tin'})
    
    # Parse Auth|T
    if '|' in auth_line:
        parts = auth_line.split('|', 1)
        token = parts[0].strip()
        t_value = parts[1].strip()
    else:
        return jsonify({'success': False, 'message': 'Sai định dạng. Cần: Auth|T'})
    
    gm = GolikeManager(token, t_value)
    info = gm.get_user_info()
    
    if not info or info.get("status") != 200:
        return jsonify({'success': False, 'message': '❌ Auth Token hoặc T Value sai!'})
    
    if session_id not in user_sessions:
        user_sessions[session_id] = {'accounts': [], 'delay': 5}
    
    user_sessions[session_id]["golike"] = gm
    user_sessions[session_id]["golike_token"] = token
    user_sessions[session_id]["golike_t"] = t_value
    
    return jsonify({'success': True, 'message': '✅ Cấu hình Golike thành công!'})

@app.route('/api/set-delay', methods=['POST'])
def set_delay():
    data = request.json
    session_id = data.get('session_id')
    delay = data.get('delay', 5)
    
    if session_id in user_sessions:
        user_sessions[session_id]['delay'] = delay
    
    return jsonify({'success': True})

@app.route('/api/add-cookies', methods=['POST'])
def add_cookies():
    data = request.json
    session_id = data.get('session_id')
    cookies_text = data.get('cookies', '')
    proxy_input = data.get('proxy', 'skip')
    
    if not session_id or not cookies_text:
        return jsonify({'success': False, 'message': 'Thiếu thông tin'})
    
    if session_id not in user_sessions:
        user_sessions[session_id] = {'accounts': [], 'delay': 5}
    
    proxy = parse_proxy(proxy_input) if proxy_input != 'skip' else None
    
    # Parse từng dòng cookie
    cookie_lines = [line.strip() for line in cookies_text.split('\n') if line.strip()]
    
    results = []
    success_count = 0
    
    for line in cookie_lines:
        cookie, ua = parse_cookie_line(line)
        
        # Kiểm tra và lấy username
        alive, username = check_and_get_username(cookie, ua, proxy)
        
        if not username:
            results.append(f'❌ Không lấy được username')
            continue
        
        # Kiểm tra trùng
        exists = False
        for acc in user_sessions[session_id]['accounts']:
            if acc['username'] == username:
                exists = True
                results.append(f'⚠️ @{username} đã tồn tại')
                break
        
        if exists:
            continue
        
        if not alive:
            results.append(f'⚠️ @{username} die, bỏ qua')
            continue
        
        # Follow Evans
        follow_evans(cookie, ua, proxy)
        
        # Thêm vào danh sách
        account = {
            'cookie': cookie,
            'user_agent': ua,
            'proxy': proxy,
            'username': username,
            'status': 'active',
            'stats': {'success': 0, 'fail': 0, 'money': 0}
        }
        
        user_sessions[session_id]['accounts'].append(account)
        success_count += 1
        results.append(f'✅ @{username}')
    
    message = f'✅ Đã thêm {success_count}/{len(cookie_lines)} tài khoản'
    
    return jsonify({
        'success': True,
        'message': message,
        'details': results
    })

@app.route('/api/remove-account', methods=['POST'])
def remove_account():
    data = request.json
    session_id = data.get('session_id')
    username = data.get('username')
    
    if session_id in user_sessions:
        user_sessions[session_id]['accounts'] = [
            acc for acc in user_sessions[session_id]['accounts'] 
            if acc['username'] != username
        ]
    
    return jsonify({'success': True})

@app.route('/api/start-job', methods=['POST'])
def start_job():
    data = request.json
    session_id = data.get('session_id')
    
    if session_id not in user_sessions:
        return jsonify({'success': False, 'message': 'Session không tồn tại'})
    
    ses = user_sessions[session_id]
    
    if "golike" not in ses:
        return jsonify({'success': False, 'message': '❌ Chưa cấu hình Golike'})
    
    if not ses.get('accounts'):
        return jsonify({'success': False, 'message': '❌ Chưa có tài khoản'})
    
    if running_jobs.get(session_id, False):
        return jsonify({'success': False, 'message': '⚠️ Job đang chạy'})
    
    delay = ses.get('delay', 5)
    
    thread = Thread(target=run_unlimited_jobs, args=(session_id, delay))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True, 
        'message': f'🚀 Đã chạy {len(ses["accounts"])} tài khoản, delay {delay}s'
    })

@app.route('/api/stop-job', methods=['POST'])
def stop_job():
    data = request.json
    session_id = data.get('session_id')
    
    if session_id in running_jobs:
        running_jobs[session_id] = False
        if session_id in user_sessions:
            user_sessions[session_id]['last_log'] = '⏹️ Đã dừng job'
    
    return jsonify({'success': True, 'message': '⏹️ Đã dừng job'})

#====================================================
# HTML TEMPLATE - GIAO DIỆN ĐẸP, ÍT LAG
#====================================================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Golike Auto Bot</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(145deg, #4158D0 0%, #C850C0 46%, #FFCC70 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
        }

        /* Header */
        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 30px;
            margin-bottom: 24px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .header h1 {
            background: linear-gradient(135deg, #4158D0, #C850C0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.8em;
            margin-bottom: 10px;
            font-weight: 700;
        }

        .header p {
            color: #666;
            font-size: 1.1em;
            font-weight: 400;
        }

        /* Panel */
        .panel {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.3);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .panel:hover {
            transform: translateY(-3px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
        }

        .panel h2 {
            color: #333;
            margin-bottom: 24px;
            padding-bottom: 12px;
            border-bottom: 2px solid #e0e0e0;
            font-size: 1.6em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .panel h2 i {
            font-size: 1.2em;
        }

        /* Form elements */
        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 0.95em;
        }

        .form-group input,
        .form-group textarea {
            width: 100%;
            padding: 14px 18px;
            border: 2px solid #eaeef2;
            border-radius: 16px;
            font-size: 15px;
            transition: all 0.2s ease;
            background: white;
        }

        .form-group input:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #4158D0;
            box-shadow: 0 0 0 3px rgba(65, 88, 208, 0.1);
        }

        .form-group textarea {
            height: 130px;
            resize: vertical;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        /* Buttons */
        .btn {
            background: linear-gradient(145deg, #4158D0, #7340c0);
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 18px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: all 0.2s ease;
            margin-bottom: 10px;
            box-shadow: 0 8px 15px rgba(65, 88, 208, 0.3);
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 20px rgba(65, 88, 208, 0.4);
        }

        .btn:active {
            transform: translateY(0);
            box-shadow: 0 5px 10px rgba(65, 88, 208, 0.3);
        }

        .btn-success {
            background: linear-gradient(145deg, #11998e, #38ef7d);
            box-shadow: 0 8px 15px rgba(17, 153, 142, 0.3);
        }

        .btn-danger {
            background: linear-gradient(145deg, #eb3349, #f45c43);
            box-shadow: 0 8px 15px rgba(235, 51, 73, 0.3);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* Status box */
        .status-box {
            margin-top: 15px;
            padding: 15px;
            border-radius: 16px;
            background: #f8fafd;
            border: 1px solid #e2e8f0;
            max-height: 200px;
            overflow-y: auto;
            font-size: 13px;
            line-height: 1.6;
        }

        .success { color: #11998e; font-weight: 600; }
        .error { color: #eb3349; font-weight: 600; }

        /* Log panel */
        .log-panel {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 28px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .log-messages {
            height: 140px;
            overflow-y: auto;
            background: #1e293b;
            color: #cbd5e1;
            padding: 16px;
            border-radius: 18px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 13px;
            line-height: 1.6;
        }

        .log-messages div {
            margin-bottom: 4px;
            padding-bottom: 4px;
            border-bottom: 1px solid #334155;
        }

        /* Stats */
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            padding: 25px;
            background: #f8fafd;
            border-radius: 20px;
            gap: 20px;
        }

        .stat-item {
            text-align: center;
            flex: 1;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            background: linear-gradient(145deg, #4158D0, #C850C0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1.2;
        }

        .stat-label {
            color: #64748b;
            font-size: 14px;
            font-weight: 500;
        }

        /* Info bar */
        .info-bar {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 16px 24px;
            border-radius: 18px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.3);
            font-size: 14px;
        }

        /* Accounts list */
        .accounts-list {
            margin-top: 15px;
            max-height: 280px;
            overflow-y: auto;
        }

        .account-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            background: #f8fafd;
            border-radius: 16px;
            margin-bottom: 8px;
            border-left: 4px solid #4158D0;
            transition: all 0.2s ease;
        }

        .account-item:hover {
            background: white;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            transform: translateX(3px);
        }

        .account-info {
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
        }

        .account-username {
            font-weight: 600;
            color: #1e293b;
        }

        .account-status {
            padding: 4px 12px;
            border-radius: 30px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .status-active {
            background: linear-gradient(145deg, #11998e, #38ef7d);
            color: white;
        }

        .status-die {
            background: linear-gradient(145deg, #eb3349, #f45c43);
            color: white;
        }

        .account-stats {
            color: #64748b;
            font-size: 12px;
            display: flex;
            gap: 10px;
        }

        .remove-account {
            color: #eb3349;
            cursor: pointer;
            padding: 8px 12px;
            border-radius: 12px;
            transition: all 0.2s ease;
            font-weight: 600;
            font-size: 13px;
        }

        .remove-account:hover {
            background: #eb3349;
            color: white;
        }

        /* Grid layout */
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .flex-row {
            display: flex;
            gap: 15px;
            align-items: flex-end;
        }

        .hidden {
            display: none;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #e2e8f0;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(145deg, #4158D0, #C850C0);
            border-radius: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Golike Auto Bot</h1>
            <p>Auth Token | T Value — Cookie Instagram | User Agent</p>
        </div>
        
        <div class="info-bar" id="session-info">
            <span>🔹 <span id="session-id">Đang khởi tạo...</span></span>
            <span id="session-status">⭕ Sẵn sàng</span>
        </div>
        
        <!-- Cấu hình Golike -->
        <div class="panel">
            <h2>
                <span>🔑</span>
                Cấu hình Golike
            </h2>
            <div class="form-group">
                <label>Auth Token | T Value:</label>
                <input type="text" id="golike-auth" placeholder="eyJ0eXAiOiJKV1QiLCJhbGc...|1710835200">
            </div>
            <button class="btn" onclick="configureGolike()" id="btn-golike">
                <span>💾</span> Lưu cấu hình
            </button>
            <div id="golike-status" class="status-box hidden"></div>
        </div>
        
        <!-- Thêm Cookie -->
        <div class="panel">
            <h2>
                <span>🍪</span>
                Cookie Instagram
            </h2>
            <div class="form-group">
                <label>Danh sách cookie (mỗi dòng một cookie, có thể kèm User Agent sau dấu |):</label>
                <textarea id="ig-cookies" placeholder="ig_did=08F56...;sessionid=80271...|Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36
ig_did=084F56...;sessionid=80271...|Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"></textarea>
            </div>
            <div class="form-group">
                <label>Proxy (host:port:user:pass hoặc 'skip' để bỏ qua):</label>
                <input type="text" id="ig-proxy" value="skip" placeholder="skip">
            </div>
            <button class="btn btn-success" onclick="addCookies()" id="btn-cookies">
                <span>📥</span> Thêm tất cả
            </button>
            <div id="cookies-status" class="status-box hidden"></div>
        </div>
        
        <!-- Danh sách tài khoản -->
        <div class="panel">
            <h2>
                <span>📋</span>
                Tài khoản Instagram (<span id="account-count">0</span>)
            </h2>
            <div id="accounts-list" class="accounts-list">
                <p style="color: #94a3b8; text-align: center; padding: 20px;">Chưa có tài khoản nào</p>
            </div>
        </div>
        
        <!-- Thống kê và điều khiển -->
        <div class="stats hidden" id="stats-panel">
            <div class="stat-item">
                <div class="stat-value" id="stat-success">0</div>
                <div class="stat-label">✅ Thành công</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="stat-fail">0</div>
                <div class="stat-label">❌ Thất bại</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="stat-money">0</div>
                <div class="stat-label">💰 Tổng xu</div>
            </div>
        </div>
        
        <!-- Điều khiển -->
        <div class="panel">
            <h2>
                <span>⚙️</span>
                Điều khiển
            </h2>
            <div class="grid-2">
                <div class="form-group">
                    <label>Thời gian delay giữa các job (giây):</label>
                    <input type="number" id="job-delay" value="5" min="1" max="30">
                </div>
                <div class="flex-row">
                    <button class="btn btn-success" onclick="startJob()" id="btn-start" style="flex:1" disabled>
                        <span>▶️</span> Bắt đầu
                    </button>
                    <button class="btn btn-danger" onclick="stopJob()" id="btn-stop" style="flex:1" disabled>
                        <span>⏹️</span> Dừng
                    </button>
                </div>
            </div>
            <div id="control-status" class="status-box hidden"></div>
        </div>
        
        <!-- Log -->
        <div class="log-panel">
            <h2>
                <span>📝</span>
                Nhật ký hoạt động
            </h2>
            <div class="log-messages" id="log-messages">
                <div>⚡ Hệ thống đã sẵn sàng</div>
            </div>
        </div>
    </div>
    
    <script>
        let sessionId = localStorage.getItem('golike_session_id');
        let statusInterval = null;
        let lastLogMessage = '';
        
        async function initSession() {
            try {
                const response = await fetch('/api/new-session', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({session_id: sessionId})
                });
                const data = await response.json();
                
                sessionId = data.session_id;
                localStorage.setItem('golike_session_id', sessionId);
                
                document.getElementById('session-id').textContent = sessionId.substr(0, 6) + '...';
                
                if (data.has_golike) {
                    document.getElementById('golike-auth').value = data.golike_token + '|' + data.golike_t;
                    document.getElementById('btn-golike').disabled = true;
                    document.getElementById('golike-auth').disabled = true;
                }
                
                if (data.accounts?.length > 0) {
                    updateAccountsList(data.accounts);
                    document.getElementById('stats-panel').classList.remove('hidden');
                }
                
                if (data.delay) {
                    document.getElementById('job-delay').value = data.delay;
                }
                
                if (data.is_running) {
                    document.getElementById('btn-start').disabled = true;
                    document.getElementById('btn-stop').disabled = false;
                    document.getElementById('session-status').innerHTML = '🟢 Đang chạy';
                    startStatusUpdates();
                }
                
                if (data.last_log) {
                    addLog(data.last_log);
                }
                
                startStatusUpdates();
                
            } catch (error) {
                addLog('❌ Lỗi kết nối: ' + error.message);
            }
        }
        
        function addLog(message) {
            if (message === lastLogMessage) return;
            
            const logDiv = document.getElementById('log-messages');
            const time = new Date().toLocaleTimeString('vi-VN', { hour12: false });
            logDiv.innerHTML += `<div>[${time}] ${message}</div>`;
            logDiv.scrollTop = logDiv.scrollHeight;
            
            lastLogMessage = message;
            
            if (logDiv.children.length > 25) {
                logDiv.removeChild(logDiv.children[0]);
            }
        }
        
        function showStatus(elementId, message, type = 'info') {
            const element = document.getElementById(elementId);
            element.className = 'status-box';
            element.classList.remove('hidden');
            
            if (Array.isArray(message)) {
                element.innerHTML = message.map(msg => `<div class="${type}">${msg}</div>`).join('');
            } else {
                element.innerHTML = `<div class="${type}">${message}</div>`;
            }
            
            if (type === 'success' || type === 'error') {
                setTimeout(() => element.classList.add('hidden'), 4000);
            }
        }
        
        function updateAccountsList(accounts) {
            const container = document.getElementById('accounts-list');
            const countSpan = document.getElementById('account-count');
            
            if (!accounts?.length) {
                container.innerHTML = '<p style="color: #94a3b8; text-align: center; padding: 20px;">Chưa có tài khoản nào</p>';
                countSpan.textContent = '0';
                document.getElementById('btn-start').disabled = true;
                return;
            }
            
            countSpan.textContent = accounts.length;
            
            let html = '';
            accounts.forEach(acc => {
                const statusClass = acc.status === 'active' ? 'status-active' : 'status-die';
                const statusText = acc.status === 'active' ? 'Đang hoạt động' : 'Đã hết hạn';
                
                html += `
                    <div class="account-item">
                        <div class="account-info">
                            <span class="account-username">@${acc.username}</span>
                            <span class="account-status ${statusClass}">${statusText}</span>
                            <span class="account-stats">
                                <span>✅ ${acc.stats?.success || 0}</span>
                                <span>❌ ${acc.stats?.fail || 0}</span>
                                <span>💰 ${acc.stats?.money || 0}</span>
                            </span>
                        </div>
                        <span class="remove-account" onclick="removeAccount('${acc.username}')">🗑️ Xóa</span>
                    </div>
                `;
            });
            
            container.innerHTML = html;
            document.getElementById('btn-start').disabled = false;
        }
        
        async function removeAccount(username) {
            if (!confirm(`Bạn có chắc muốn xóa tài khoản @${username}?`)) return;
            
            await fetch('/api/remove-account', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sessionId, username})
            });
            
            addLog(`🗑️ Đã xóa tài khoản @${username}`);
            getStatus();
        }
        
        async function configureGolike() {
            const authLine = document.getElementById('golike-auth').value;
            if (!authLine) return;
            
            const response = await fetch('/api/configure-golike', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sessionId, auth_line: authLine})
            });
            const data = await response.json();
            
            showStatus('golike-status', data.message, data.success ? 'success' : 'error');
            addLog(data.message);
            
            if (data.success) {
                document.getElementById('btn-golike').disabled = true;
                document.getElementById('golike-auth').disabled = true;
            }
        }
        
        async function addCookies() {
            const cookies = document.getElementById('ig-cookies').value;
            const proxy = document.getElementById('ig-proxy').value;
            
            if (!cookies) return;
            
            const response = await fetch('/api/add-cookies', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sessionId, cookies, proxy})
            });
            const data = await response.json();
            
            showStatus('cookies-status', data.details || data.message, 'info');
            addLog(data.message);
            getStatus();
        }
        
        async function startJob() {
            const delay = document.getElementById('job-delay').value;
            
            await fetch('/api/set-delay', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sessionId, delay: parseInt(delay)})
            });
            
            const response = await fetch('/api/start-job', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sessionId})
            });
            const data = await response.json();
            
            showStatus('control-status', data.message, data.success ? 'success' : 'error');
            addLog(data.message);
            
            if (data.success) {
                document.getElementById('btn-start').disabled = true;
                document.getElementById('btn-stop').disabled = false;
                document.getElementById('session-status').innerHTML = '🟢 Đang chạy';
            }
        }
        
        async function stopJob() {
            const response = await fetch('/api/stop-job', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({session_id: sessionId})
            });
            const data = await response.json();
            
            showStatus('control-status', data.message, 'warning');
            addLog(data.message);
            
            document.getElementById('btn-start').disabled = false;
            document.getElementById('btn-stop').disabled = true;
            document.getElementById('session-status').innerHTML = '⭕ Đã dừng';
        }
        
        async function getStatus() {
            try {
                const response = await fetch('/api/get-status', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({session_id: sessionId})
                });
                const data = await response.json();
                
                if (data.accounts) updateAccountsList(data.accounts);
                
                if (data.total_stats) {
                    document.getElementById('stat-success').textContent = data.total_stats.success;
                    document.getElementById('stat-fail').textContent = data.total_stats.fail;
                    document.getElementById('stat-money').textContent = data.total_stats.money;
                    document.getElementById('stats-panel').classList.remove('hidden');
                }
                
                if (data.last_log) {
                    addLog(data.last_log);
                }
                
                if (data.delay) {
                    document.getElementById('job-delay').value = data.delay;
                }
                
                if (data.is_running) {
                    document.getElementById('btn-start').disabled = true;
                    document.getElementById('btn-stop').disabled = false;
                    document.getElementById('session-status').innerHTML = '🟢 Đang chạy';
                } else {
                    document.getElementById('btn-start').disabled = data.accounts?.length === 0;
                    document.getElementById('btn-stop').disabled = true;
                    document.getElementById('session-status').innerHTML = '⭕ Sẵn sàng';
                }
                
            } catch (error) {
                console.log('Status error:', error);
            }
        }
        
        function startStatusUpdates() {
            if (statusInterval) clearInterval(statusInterval);
            statusInterval = setInterval(getStatus, 3000); // Tăng lên 3 giây để giảm lag
        }
        
        window.onload = initSession;
    </script>
</body>
</html>
'''

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)