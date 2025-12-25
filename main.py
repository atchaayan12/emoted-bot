
import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime, timedelta
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

import random

def fix_num(num):
    try:
        return f"{int(num):,}"
    except:
        return str(num)

def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶GUILD DETAILS◀◀◀◀
Achievements: {data['achievements']}

Balance : {fix_num(data['balance'])}

Clan Name : {data['clan_name']}

Expire Time : {fix_num(data['guild_details']['expire_time'])}

Members Online : {fix_num(data['guild_details']['members_online'])}

Regional : {data['guild_details']['regional']}

Reward Time : {fix_num(data['guild_details']['reward_time'])}

Total Members : {fix_num(data['guild_details']['total_members'])}

ID : {fix_num(data['id'])}

Last Active : {fix_num(data['last_active'])}

Level : {fix_num(data['level'])}

Rank : {fix_num(data['rank'])}

Region : {data['region']}

Score : {fix_num(data['score'])}

Timestamp1 : {fix_num(data['timestamp1'])}

Timestamp2 : {fix_num(data['timestamp2'])}

Welcome Message: {data['welcome_message']}

XP: {fix_num(data['xp'])}

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY CLOUD ENGINE
            """
            return msg
        else:
            msg = f"""
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Failed to get info, please try again later!!
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY CLOUD ENGINE
            """
            return msg
    except:
        return "[FF0000]Error getting clan info"

def talk_with_ai(question):
    character_prompt = ""

    full_prompt = f"{character_prompt}\n\nUser asked: {question}\n\nRespond as CLOUD ENGINE in SIMPLE HINDENGLISH using basic words like 'tu ek n a l a y a k he samjha' with AGGRESSIVE roast and SPACED OUT gali words. Use simple words only:"

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    headers = {
        'Content-Type': 'application/json',
        'X-goog-api-key': 'AIzaSyCl61gFgKB9hZK0Bf7rFbgQwSHlGyleSYE'
    }
    data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": full_prompt
                    }
                ]
            }
        ]
    }
    try:
        res = requests.post(url, headers=headers, json=data, timeout=30)
        if res.status_code == 200:
            response_data = res.json()
            if 'candidates' in response_data and len(response_data['candidates']) > 0:
                content = response_data['candidates'][0]['content']['parts'][0]['text']
                return content
            else:
                return "Arre yaar, kya ho gaya? CLOUD ENGINE ko response nahi mil raha! 😤"
        else:
            return f"Oops! CLOUD ENGINE ka mood off hai, API error {res.status_code} 😅"
    except requests.exceptions.RequestException as e:
        return f"Arre bhai, CLOUD ENGINE ka internet slow hai! Connection fail ho gaya 😭"




def send_likes(uid):
    try:
        likes_api_response = requests.get(
             f"https://yourlikeapi/like?uid={uid}&server_name={server2}&x-vercel-set-bypass-cookie=true&x-vercel-protection-bypass={BYPASS_TOKEN}",
             timeout=15
             )
        if likes_api_response.status_code != 200:
            return f"""[C][B][FF0000]━━━━━
[FFFFFF]Like API Error!
Status Code: {likes_api_response.status_code}
Please check if the uid is correct.
━━━━━"""
        api_json_response = likes_api_response.json()
        player_name = api_json_response.get('PlayerNickname', 'Unknown')
        likes_before = api_json_response.get('LikesbeforeCommand', 0)
        likes_after = api_json_response.get('LikesafterCommand', 0)
        likes_added = api_json_response.get('LikesGivenByAPI', 0)
        status = api_json_response.get('status', 0)
        if status == 1 and likes_added > 0:
            return f"""[C][B][11EAFD]━━━━━━━━━━━━
[FFFFFF]Likes Status:
[00FF00]Likes Sent Successfully!
[FFFFFF]Player Name : [00FF00]{player_name}
[FFFFFF]Likes Added : [00FF00]{likes_added}
[FFFFFF]Likes Before : [00FF00]{likes_before}
[FFFFFF]Likes After : [00FF00]{likes_after}
[C][B][11EAFD]━━━━━━━━━━━━
[C][B][FFB300]Subscribe: [FFFFFF]CLOUD ENGINE [00FF00]!!"""
        elif status == 2 or likes_before == likes_after:
            return f"""[C][B][FF0000]━━━━━━━━━━━━
[FFFFFF]No Likes Sent!
[FF0000]You have already taken likes with this UID.
Try again after 24 hours.
[FFFFFF]Player Name : [FF0000]{player_name}
[FFFFFF]Likes Before : [FF0000]{likes_before}
[FFFFFF]Likes After : [FF0000]{likes_after}
[C][B][FF0000]━━━━━━━━━━━━"""
        else:
            return f"""[C][B][FF0000]━━━━━━━━━━━━
[FFFFFF]Unexpected Response!
Something went wrong.
Please try again or contact support.
━━━━━━━━━━━━"""
    except requests.exceptions.RequestException:
        return f"""[C][B][FF0000]━━━━━
[FFFFFF]Like API Connection Failed!
Is the API server (app.py) running?
━━━━━"""
    except Exception as e:
        return f"""[C][B][FF0000]━━━━━
[FFFFFF]An unexpected error occurred:
[FF0000]{str(e)}
━━━━━"""

EMOTE_ALIASES = {
    "m10": 909000081, "ak": 909000063, "ump": 909000098, "mp40": 909000075,
    "mp40v2": 909040010, "scar": 909000068, "xm8": 909000085, "mp5": 909033002,
    "m4a1": 909033001, "famas": 909000090, "m1887": 909035007, "thompson": 909038010,
    "g18": 909038012, "woodpecker": 909042008, "parafal": 909045001, "groza": 909041005,
    "p90": 909049010, "m60": 909051003, "fist": 909037011,

    "ride": 909051014, "circle": 909050009, "petals": 909051013, "bow": 909051012,
    "bike": 909051010, "shower": 909051004, "dream": 909051002, "angelic": 909051001,
    "paint": 909048015, "sword": 909044015, "flare": 909041008, "owl": 909049003,
    "thor": 909050008, "bigdill": 909049001, "csgm": 909041013, "mapread": 909050014,
    "tomato": 909050015, "ninja": 909050002, "level100": 909042007, "auraboat": 909050028,
    "flyingguns": 909049012, "heart": 909000045, "flag": 909000034, "pushup": 909000012,
    "devil": 909000020, "shootdance": 909000008, "chicken": 909000006, "throne": 909000014,
    "rose": 909000010, "valentine": 909038004, "rampage": 909034001, "guildflag": 909049017,
    "fish": 909040004, "inosuke": 909041003, "brgm": 909041012,
    "naruto": 909050003, "kabuto": 909050002, "minato": 909050006, "football": 909048016,
    "p": 909000012, "t": 909000014, "r": 909000010, "l100": 909042007
}

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.urandom(24)

# ===== ADD THIS HERE =====
@app.route('/api/discord/create-account', methods=['POST'])
def discord_create_account():
    print("🎯 DISCORD BOT REQUEST RECEIVED!")
    try:
        data = request.get_json()
        print(f"📦 Data from bot: {data}")
        
        # Just return success for testing
        return jsonify({
            'status': 'success', 
            'message': 'Account created (test)!'
        })
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Add a test route
@app.route('/test', methods=['GET'])
def test_route():
    return "✅ Flask is working!"

# ===== DISCORD BOT SETUP =====
# Initialize Discord bot (add your bot token)


# ⚠️ ADD THIS MISSING LINE ⚠️

USERS_FILE = 'users.json'
ADMIN_USERNAME = 'AGENT'
ADMIN_PASSWORD = '8600'
LOOP = None

online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
key = None
iv = None
region = None
server2 = "bd"
key2 = "YOUR_API_KEY"
BYPASS_TOKEN = "YOUR_BYPASS_TOKEN"


BOT_CREDENTIALS = {
    'india': [
        {'uid': '4288085957', 'password': 'E21A6053F4BF61DA48051BB4DBCEE7237C7D68FC2AB717D85D2540B0678BEEB2'},
    ],
    'bangladesh': [
        {'uid': '4287216779', 'password': 'BY_CLOUDDDD-2Q4VL5L-OFFLINE'},
        {'uid': '4287216821', 'password': 'BY_CLOUDDDD-FW9YRUH-OFFLINE'},
        {'uid': '4287216847', 'password': 'BY_CLOUDDDD-CYTO8KQ-OFFLINE'},
        {'uid': '4287216871', 'password': 'BY_CLOUDDDD-XMC3UY9-OFFLINE'},
        {'uid': '4287216902', 'password': 'BY_CLOUDDDD-X1WJXZ4-OFFLINE'},
    ]
}
class BotInstance:
    def __init__(self, bot_id, uid, password):
        self.bot_id = bot_id
        self.uid = uid
        self.password = password
        self.online_writer = None
        self.whisper_writer = None
        self.key = None
        self.iv = None
        self.region = None
        self.is_connected = False
        self.lock = threading.Lock()
        self.current_team_code = None

class BotManager:
    def __init__(self, server_name):
        self.server_name = server_name
        self.team_code_to_bot = {}
        self.bot_instances = []
        self.bot_index = 0
        self.lock = threading.Lock()

    def get_or_assign_bot(self, team_code):
        with self.lock:
            if team_code in self.team_code_to_bot:
                return self.team_code_to_bot[team_code]

            if not self.bot_instances:
                return None

            assigned_bot = self.bot_instances[self.bot_index % len(self.bot_instances)]
            self.bot_index += 1
            self.team_code_to_bot[team_code] = assigned_bot
            print(f"[BotManager-{self.server_name}] Team code {team_code} assigned to Bot {assigned_bot.bot_id}")
            return assigned_bot

bot_managers = {
    'india': BotManager('india'),
    'bangladesh': BotManager('bangladesh')
}

async def encrypted_proto(encoded_hex):
    key_aes = b'Yg&tc%DEuh6%Zc^8'
    iv_aes = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key_aes, AES.MODE_CBC, iv_aes)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload

async def GeNeRaTeAccEss(uid , password, retry_count=3, retry_delay=2.0):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51"}
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}

    last_error = None
    for attempt in range(1, retry_count + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=Hr, data=data, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        try:
                            response_data = await response.json()
                            open_id = response_data.get("open_id")
                            access_token = response_data.get("access_token")
                            if open_id and access_token:
                                if attempt > 1:
                                    print(f"[Auth] Success on attempt {attempt}")
                                return (open_id, access_token)
                            else:
                                last_error = f"Missing open_id or access_token in response"
                        except Exception as json_error:
                            last_error = f"Failed to parse JSON response: {json_error}"
                    else:
                        try:
                            error_text = await response.text()
                            last_error = f"HTTP {response.status}: {error_text[:200]}"
                        except:
                            last_error = f"HTTP {response.status}: No error details available"

            if attempt < retry_count:
                wait_time = retry_delay * attempt
                print(f"[Auth] Attempt {attempt}/{retry_count} failed: {last_error}")
                print(f"[Auth] Retrying in {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)
            else:
                print(f"[Auth] All {retry_count} attempts failed. Last error: {last_error}")

        except asyncio.TimeoutError:
            last_error = "Request timeout (15s)"
            if attempt < retry_count:
                wait_time = retry_delay * attempt
                print(f"[Auth] Attempt {attempt}/{retry_count} timed out. Retrying in {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)
        except Exception as e:
            last_error = f"Exception: {str(e)}"
            if attempt < retry_count:
                wait_time = retry_delay * attempt
                print(f"[Auth] Attempt {attempt}/{retry_count} error: {last_error}. Retrying in {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)

    return (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51"}
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggwhitehawk.com/MajorLogin"
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51"}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    Hr = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51"}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto

async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto

async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'

async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT, bot_instance=None):
    if bot_instance:
        if TypE == 'ChaT' and ChaT and bot_instance.whisper_writer:
            bot_instance.whisper_writer.write(PacKeT)
            await bot_instance.whisper_writer.drain()
        elif TypE == 'OnLine' and bot_instance.online_writer:
            bot_instance.online_writer.write(PacKeT)
            await bot_instance.online_writer.drain()
        else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)'
    else:
        if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
        elif TypE == 'OnLine': online_writer.write(PacKeT) ; await online_writer.drain()
        else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)'

async def TcPOnLine(ip, port, key, iv, AutHToKen, bot_instance=None, reconnect_delay=0.5):
    global online_writer , spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , XX , uid , Spy,data2, Chat_Leave
    writer_ref = bot_instance.online_writer if bot_instance else None
    while True:
        try:
            reader , writer = await asyncio.wait_for(asyncio.open_connection(ip, int(port)), timeout=10.0)
            if bot_instance:
                bot_instance.online_writer = writer
                writer_ref = bot_instance.online_writer
            else:
                online_writer = writer
                writer_ref = online_writer
            bytes_payload = bytes.fromhex(AutHToKen)
            writer_ref.write(bytes_payload)
            await writer_ref.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break

                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        print(data2.hex()[10:])
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        print(packet)
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT, bot_instance)


                        message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! '
                        P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P, bot_instance)

                    except:
                        if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                            try:
                                print(data2.hex()[10:])
                                packet = await DeCode_PackEt(data2.hex()[10:])
                                print(packet)
                                packet = json.loads(packet)
                                OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                                JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT, bot_instance)


                                message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! \n\n{get_random_color()}- Commands : @a {xMsGFixinG("player_uid")} {xMsGFixinG("909000001")}\n\n[00FF00]Dev : @{xMsGFixinG("CLOUD ENGINE")}'
                                P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                                await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P, bot_instance)
                            except:
                                pass

            if bot_instance:
                if bot_instance.online_writer:
                    try:
                        bot_instance.online_writer.close()
                        await bot_instance.online_writer.wait_closed()
                    except:
                        pass
                    bot_instance.online_writer = None
            else:
                try:
                    online_writer.close()
                    await online_writer.wait_closed()
                except:
                    pass
                online_writer = None

        except asyncio.TimeoutError:
            if bot_instance:
                bot_instance.online_writer = None
                bot_instance.is_connected = False
            else:
                online_writer = None
            print(f"[Bot {bot_instance.bot_id if bot_instance else 'Global'}] ❌ Connection timeout to {ip}:{port} (Online server) - Reconnecting...")
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as conn_error:
            if bot_instance:
                bot_instance.online_writer = None
                bot_instance.is_connected = False
            else:
                online_writer = None
            print(f"[Bot {bot_instance.bot_id if bot_instance else 'Global'}] ❌ Connection error to {ip}:{port} (Online server): {conn_error} - Reconnecting immediately...")
        except Exception as e:
            if bot_instance:
                bot_instance.online_writer = None
                bot_instance.is_connected = False
            else:
                online_writer = None
            print(f"[Bot {bot_instance.bot_id if bot_instance else 'Global'}] ❌ Error with {ip}:{port} (Online server): {e} - Reconnecting...")
        await asyncio.sleep(0.1)

async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , bot_instance=None, reconnect_delay=0.5):
    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave
    writer_ref = bot_instance.whisper_writer if bot_instance else None
    while True:
        try:
            reader , writer = await asyncio.wait_for(asyncio.open_connection(ip, int(port)), timeout=10.0)
            if bot_instance:
                bot_instance.whisper_writer = writer
                writer_ref = bot_instance.whisper_writer
            else:
                whisper_writer = writer
                writer_ref = whisper_writer
            bytes_payload = bytes.fromhex(AutHToKen)
            writer_ref.write(bytes_payload)
            await writer_ref.drain()

            await asyncio.sleep(0.3)

            if not writer_ref.is_closing():
                ready_event.set()
            else:
                raise ConnectionError("Connection closed immediately after authentication")
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if writer_ref: writer_ref.write(pK) ; await writer_ref.drain()
            while True:
                data = await reader.read(9999)
                if not data: break

                if data.hex().startswith("120000"):

                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None


                    if response:

                        parts = inPuTMsG.strip().split()

                        if len(parts) >= 2 and parts[0].startswith('/') and parts[0][1:] in EMOTE_ALIASES:
                            emote_alias = parts[0][1:]
                            emote_id = EMOTE_ALIASES[emote_alias]

                            is_auto_mode = len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit()
                            is_squad_mode = len(parts) >= 2 and parts[1].isdigit()

                            if not is_squad_mode and not is_auto_mode:
                                message = f'[B][C][FF0000]ERROR:\nভুল কমান্ড ফরম্যাট।\nব্যবহার:\n১. স্কোয়াডে থাকলে: /{emote_alias} (uid) [uid2...]\n২. Guild/Friend চ্যাটে: /{emote_alias} (teamcode) (uid) [uid2...]'
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                response = None
                                continue

                            uid_start_index = 1 if not is_auto_mode else 2

                            target_uids = []
                            for i in range(uid_start_index, min(uid_start_index + 5, len(parts))):
                                if parts[i].isdigit():
                                    target_uids.append(int(parts[i]))
                                else:
                                    break

                            if not target_uids:
                                message = f'[B][C][FF0000]ERROR:\nUID অবশ্যই সংখ্যা হতে হবে।\nব্যবহার:\n১. স্কোয়াডে থাকলে: /{emote_alias} (uid) [uid2...]\n২. Guild/Friend চ্যাটে: /{emote_alias} (teamcode) (uid) [uid2...]'
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                response = None
                                continue


                            if is_auto_mode:
                                team_code = parts[1]

                                try:
                                    EM = await GenJoinSquadsPacket(team_code , key , iv, region)
                                    await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , EM, bot_instance)
                                    await asyncio.sleep(0.15)

                                    message = f'[B][C]{get_random_color()}\nACITVE Emote /{emote_alias} on -> {xMsGFixinG(target_uids[0])}{" and others" if len(target_uids) > 1 else ""}\n'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                    for target_uid in target_uids:
                                        H = await Emote_k(target_uid, emote_id, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)

                                    await asyncio.sleep(0.2)

                                    leave = await ExiT(None, key, iv, region)
                                    await SEndPacKeT(whisper_writer , online_writer , 'OnLine' , leave, bot_instance)

                                    message = f'[B][C]{get_random_color()}\nBot left the squad after performing emote.'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                except Exception as e:
                                    message = f'[B][C][FF0000]ERROR: Auto Emote Failed. Team Code or UID invalid. Error: {str(e)}'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)


                            elif is_squad_mode:
                                try:
                                    chatdata['5']['data']['16']
                                    print('msg in private/guild. Squad Mode not applicable.')
                                    message = f"[B][C]{get_random_color()}\n\nCommand Available OnLy In SQuaD, or use the format: /{emote_alias} (teamcode) (uid) in Guild/Private chat! \n\n"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                except:
                                    print(f'msg in squad: /{emote_alias} -> {target_uids}')
                                    message = f'[B][C]{get_random_color()}\nACITVE Emote /{emote_alias} on -> {xMsGFixinG(target_uids[0])}{" and others" if len(target_uids) > 1 else ""}\n'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                    for target_uid in target_uids:
                                        H = await Emote_k(target_uid, emote_id, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)

                            response = None


                        if response and inPuTMsG.strip().startswith('/e'):

                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nCommand Available OnLy In SQuaD ! \n\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                            except:
                                print('msg in squad')

                                parts = inPuTMsG.strip().split()
                                print(response.Data.chat_type, uid, chat_id)
                                message = f'[B][C]{get_random_color()}\nACITVE TarGeT -> {xMsGFixinG(uid)}\n'

                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)

                                uid2 = uid3 = uid4 = uid5 = None
                                s = False

                                try:
                                    uid = int(parts[1])
                                    uid2 = int(parts[2])
                                    uid3 = int(parts[3])
                                    uid4 = int(parts[4])
                                    uid5 = int(parts[5])
                                    idT = int(parts[5])

                                except ValueError as ve:
                                    print("ValueError:", ve)
                                    s = True

                                except Exception:
                                    idT = len(parts) - 1
                                    idT = int(parts[idT])
                                    print(idT)
                                    print(uid)

                                if not s:
                                    try:
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                        H = await Emote_k(uid, idT, key, iv,region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)

                                        if uid2:
                                            H = await Emote_k(uid2, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)
                                        if uid3:
                                            H = await Emote_k(uid3, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)
                                        if uid4:
                                            H = await Emote_k(uid4, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)
                                        if uid5:
                                            H = await Emote_k(uid5, idT, key, iv,region)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', H, bot_instance)


                                    except Exception as e:
                                        pass


                        if inPuTMsG.strip().startswith('5') and len(inPuTMsG.strip()) == 1:
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\nAccept My Invitation Fast\n"
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                PAc = await OpEnSq(key, iv, region)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc, bot_instance)
                                C = await cHSq(5, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C, bot_instance)
                                V = await SEnd_InV(5, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V, bot_instance)
                                E = await ExiT(None, key, iv, region)
                                await asyncio.sleep(3)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E, bot_instance)
                            except:
                                print('msg in squad')

                        if inPuTMsG.strip().startswith('solo'):
                            try:
                                online_writer_ref = bot_instance.online_writer if bot_instance else online_writer
                                if online_writer_ref:
                                    leave = await ExiT(uid, key, iv, region)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave, bot_instance)
                                    message = f"[C][B][00FF00]Left squad successfully"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                            except Exception as e:
                                print(f"Error in /solo: {e}")

                        if inPuTMsG.strip().startswith('teamcode'):
                            try:
                                parts = inPuTMsG.strip().split()
                                if len(parts) < 2:
                                    message = f"[C][B][FF0000]Please provide team code\nExample: teamcode (code)"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                else:
                                    CodE = parts[1].strip()
                                    try:
                                        dd = chatdata['5']['data']['16']
                                        print('msg in private')
                                        EM = await GenJoinSquadsPacket(CodE, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', EM, bot_instance)
                                        message = f"[C][B][00FF00]Joining team {CodE}..."
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                    except:
                                        print('msg in squad')
                            except Exception as e:
                                print(f"Error in /teamcode: {e}")

                        if inPuTMsG.strip().startswith('lag'):
                            try:
                                parts = inPuTMsG.strip().split()
                                if len(parts) < 2:
                                    message = f"[C][B][FF0000]Please provide team code\nExample: lag (code) [seconds]"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                else:
                                    team_code = parts[1]
                                    duration = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 10
                                    if duration < 2: duration = 2
                                    if duration > 60: duration = 60

                                    message = f"[C][B][32CD32]Lagging team {team_code}\nDuration: {duration} seconds"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                    online_writer_ref = bot_instance.online_writer if bot_instance else online_writer
                                    if online_writer_ref:
                                        overall_start_time = time.time()
                                        total_packets = 0

                                        while time.time() - overall_start_time < duration:
                                            try:
                                                join_packet = await GenJoinSquadsPacket(team_code, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet, bot_instance)
                                                await asyncio.sleep(0.01)

                                                leave_packet = await ExiT(None, key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet, bot_instance)
                                                await asyncio.sleep(0.01)
                                                total_packets += 1
                                            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as conn_error:
                                                print(f"Connection error during lag: {conn_error}")
                                                await asyncio.sleep(1)
                                                break
                                            except Exception as e:
                                                print(f"Error in lag loop: {e}")
                                                await asyncio.sleep(0.1)

                                        message = f"[C][B][00FF00]Lag done\nSent {total_packets} packets in {duration}s"
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                    else:
                                        message = "[C][B][FF0000]Online writer not available"
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                            except Exception as e:
                                print(f"Error in /lag: {e}")
                                try:
                                    message = f"[C][B][FF0000]Error in lag command: {str(e)}"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                except:
                                    pass

                        if inPuTMsG.strip().startswith('attack'):
                            try:
                                parts = inPuTMsG.strip().split()
                                if len(parts) < 2:
                                    message = f"[C][B][FF0000]Please provide team code\nExample: attack (code)"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                else:
                                    team_code = parts[1]
                                    message = f"[C][B][FFA500]Attacking team {team_code}"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                    online_writer_ref = bot_instance.online_writer if bot_instance else online_writer
                                    if online_writer_ref:
                                        start_time = time.time()
                                        start_packet = await FS(key, iv, region)
                                        leave_packet = await ExiT(None, key, iv, region)

                                        try:
                                            while time.time() - start_time < 45:
                                                try:
                                                    join_packet = await GenJoinSquadsPacket(team_code, key, iv, region)
                                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet, bot_instance)
                                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', start_packet, bot_instance)
                                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet, bot_instance)
                                                    await asyncio.sleep(0.15)
                                                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as conn_error:
                                                    print(f"Connection error during attack: {conn_error}")
                                                    break
                                                except Exception as e:
                                                    print(f"Error in attack loop: {e}")
                                                    await asyncio.sleep(0.01)
                                        except Exception as e:
                                            print(f"Error in attack execution: {e}")

                                    message = f"[C][B][00FF00]Attack done"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                            except Exception as e:
                                print(f"Error in /attack: {e}")

                        if inPuTMsG.strip().startswith('start') and not inPuTMsG.strip().startswith('startgame'):
                            try:
                                parts = inPuTMsG.strip().split()
                                if len(parts) < 2:
                                    message = f"[C][B][FF0000]Please provide team code\nExample: start (code) [count]"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                else:
                                    team_code = parts[1]
                                    spam_count = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 20
                                    if spam_count > 50: spam_count = 50

                                    online_writer_ref = bot_instance.online_writer if bot_instance else online_writer
                                    if online_writer_ref:
                                        join_packet = await GenJoinSquadsPacket(team_code, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet, bot_instance)
                                        await asyncio.sleep(2)

                                        message = f"[C][B][FF0000]Spamming start {spam_count} times"
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                        start_packet = await FS(key, iv, region)
                                        for _ in range(spam_count):
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', start_packet, bot_instance)
                                            await asyncio.sleep(0.2)

                                        leave_packet = await ExiT(None, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet, bot_instance)

                                        message = f"[C][B][00FF00]Force start done"
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                    else:
                                        message = "[C][B][FF0000]Online writer not available\nPlease wait for connection"
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                            except Exception as e:
                                print(f"Error in /start: {e}")

                        if inPuTMsG.strip().startswith('ai'):
                            try:
                                if len(inPuTMsG.strip()) <= 2 or inPuTMsG.strip() == 'ai':
                                    message = "[C][B][FF0000]Please provide a question after ai\nExample: ai What is Free Fire?"
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                else:
                                    question = inPuTMsG.strip()[2:].strip()
                                    if not question:
                                        message = "[C][B][FF0000]Please provide a question after ai"
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                    else:
                                        message = "[C][B][FFFFFF]Connecting to AI..."
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)

                                        try:
                                            ai_response = talk_with_ai(question)
                                            if ai_response:
                                                P = await SEndMsG(response.Data.chat_type, ai_response, uid, chat_id, key, iv)
                                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                            else:
                                                message = "[C][B][FF0000]AI response is empty. Please try again."
                                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                        except Exception as ai_error:
                                            print(f"AI API error: {ai_error}")
                                            message = "[C][B][FF0000]Error connecting to AI. Please try again."
                                            P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                            except Exception as e:
                                print(f"Error in /ai: {e}")
                                try:
                                    message = "[C][B][FF0000]Error with AI command. Please try again."
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P, bot_instance)
                                except:
                                    pass

                        if inPuTMsG.strip().lower() in ("hi", "hello", "jaisreeram", "help", "fen"):
                            uid = response.Data.uid
                            chat_id = response.Data.Chat_ID
                            message = f"""[FFFFFF]ALL COMMANDS

[00FF00]teamcode (code) - Join Team
[00FF00]emote (uid) (id) - Emote
[00FF00]5 - Make 5 Group
[00FF00]solo - Leave Squad
[00FF00]lag (code) [sec] - Lag Team
[00FF00]attack (code) - Attack
[00FF00]start (code) - Force Start
[00FF00]ai (question) - Chat AI

[00FF7F][B]★ সহজ ইমোট কমান্ড (Emote Shortcut) ★
[FFFFFF][b]১. স্কোয়াডে থাকলে: /(emote_name) (uid) [uid2...]
[FFFFFF][b]২. Guild/Friend চ্যাটে (Auto-Mode): [00FF00]/(emote_name) (teamcode) (uid) [uid2...]
[FFFFFF][b]উদাহরণ (Auto-Mode): /ak 12345 521475527
[FFFFFF][b]উপলব্ধ ইমোট: [00FF00]{", ".join(EMOTE_ALIASES.keys())}

[C][B][FFB300]OWNER: CLOUD ENGINE
[00FFFF]━━━━━━━━━━━━"""
                            P = await SEndMsG(response.Data.chat_type , message , uid , chat_id , key , iv)
                            await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P, bot_instance)
                        response = None

            if bot_instance:
                if bot_instance.whisper_writer:
                    try:
                        bot_instance.whisper_writer.close()
                        await bot_instance.whisper_writer.wait_closed()
                    except:
                        pass
                    bot_instance.whisper_writer = None
            else:
                try:
                    whisper_writer.close()
                    await whisper_writer.wait_closed()
                except:
                    pass
                whisper_writer = None
        except asyncio.TimeoutError:
            if bot_instance:
                bot_instance.whisper_writer = None
                bot_instance.is_connected = False
            else:
                whisper_writer = None
            print(f"[Bot {bot_instance.bot_id if bot_instance else 'Global'}] ❌ Connection timeout to {ip}:{port} (Chat server) - Reconnecting...")
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as conn_error:
            if bot_instance:
                bot_instance.whisper_writer = None
                bot_instance.is_connected = False
            else:
                whisper_writer = None
            print(f"[Bot {bot_instance.bot_id if bot_instance else 'Global'}] ❌ Connection error to {ip}:{port} (Chat server): {conn_error} - Reconnecting immediately...")
        except Exception as e:
            if bot_instance:
                bot_instance.whisper_writer = None
                bot_instance.is_connected = False
            else:
                whisper_writer = None
            print(f"[Bot {bot_instance.bot_id if bot_instance else 'Global'}] ❌ Error with {ip}:{port} (Chat server): {e} - Reconnecting...")
        await asyncio.sleep(0.1)
async def perform_emote_sequence(uids_list, emote_id, team_code_str, bot_instance=None):
    bot_key = bot_instance.key if bot_instance else key
    bot_iv = bot_instance.iv if bot_instance else iv
    bot_region = bot_instance.region if bot_instance else region

    try:
        print(f"👻 GHOST MODE ACTIVATED")
        
        # 1. Quick join (0.5s)
        join_packet = await GenJoinSquadsPacket(team_code_str, bot_key, bot_iv, bot_region)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet, bot_instance)
        await asyncio.sleep(0.3)
        
        # 2. Rapid emote burst (all in 0.2s)
        emote_tasks = []
        for uid_target in uids_list:
            emote_packet = await Emote_k(uid_target, emote_id, bot_key, bot_iv, bot_region)
            # Send immediately without waiting
            emote_tasks.append(SEndPacKeT(whisper_writer, online_writer, 'OnLine', emote_packet, bot_instance))
        
        # Send all emotes as fast as possible
        await asyncio.gather(*emote_tasks, return_exceptions=True)
        
        # 3. Bare minimum wait for packet processing (0.3s)
        await asyncio.sleep(0.2)
        
        # 4. Instant leave
        leave_packet = await ExiT(None, bot_key, bot_iv, bot_region)
        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet, bot_instance)
        
        print(f"✅ Ghost operation: ~0.8s total")
        return True

    except Exception as e:
        print(f"❌ Ghost error: {e}")
        try:
            leave_packet = await ExiT(None, bot_key, bot_iv, bot_region)
            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet, bot_instance)
        except:
            pass
        return False

    except Exception as e:
        print(f"Error in emote sequence: {e}")
        # Ensure bot leaves even if there's an error
        try:
            leave_packet = await ExiT(None, bot_key, bot_iv, bot_region)
            await SEndPacKeT(None, None, 'OnLine', leave_packet, bot_instance)
        except:
            pass
        return False



def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                data = f.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except json.JSONDecodeError:
            return {}
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}
    else:
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump({}, f, indent=2)
            print(f"Created {USERS_FILE} file")
        except Exception as e:
            print(f"Error creating {USERS_FILE}: {e}")
        return {}

def save_users(users):
    try:
        file_dir = os.path.dirname(USERS_FILE)
        if file_dir and not os.path.exists(file_dir):
            os.makedirs(file_dir, exist_ok=True)

        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        print(f"Error saving users: {e}")
        raise

def check_user_expiry(username):
    users = load_users()
    if username not in users:
        return True

    user = users[username]
    try:
        expires_at = datetime.fromisoformat(user['expires_at'])
        now = datetime.now()

        if expires_at.date() < now.date():
            return True

        if expires_at.date() == now.date():
            return now > expires_at

        return False
    except Exception as e:
        print(f"Error checking expiry for {username}: {e}")
        return True

def is_user_valid(username):
    users = load_users()
    if username not in users:
        return False

    user = users[username]
    if user.get('status') != 'active':
        return False

    return not check_user_expiry(username)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))

        if not is_user_valid(session['username']):
            session.clear()
            return redirect(url_for('login') + '?expired=1')

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session or not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET'])
def login():
    load_users()

    if 'username' in session:
        if is_user_valid(session['username']):
            return redirect(url_for('index'))
        else:
            session.clear()

    return render_template('login.html')

@app.route('/auth/login', methods=['POST'])
def auth_login():
    try:
        load_users()
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'status': 'error', 'message': 'Username and password are required'}), 400

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['username'] = username
            session['admin'] = True
            return jsonify({'status': 'success', 'message': 'Admin login successful', 'redirect': '/admin'})

        users = load_users()
        if username not in users:
            return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401

        user = users[username]

        if not check_password_hash(user['password'], password):
            return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401

        if user.get('status') != 'active':
            return jsonify({'status': 'error', 'message': 'Your account is inactive. Please contact admin.'}), 403

        try:
            expires_at = datetime.fromisoformat(user['expires_at'])
            now = datetime.now()

            if expires_at < now:
                expiry_date = expires_at.strftime('%Y-%m-%d')
                return jsonify({'status': 'error', 'message': f'Your account expired on {expiry_date}. Please contact admin to renew your access.'}), 403
        except Exception as e:
            print(f"❌ Error checking expiry during login: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'status': 'error', 'message': 'Error checking account expiry. Please contact admin.'}), 500

        session['username'] = username
        session['admin'] = False
        return jsonify({'status': 'success', 'message': 'Login successful', 'redirect': '/'})

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'status': 'error', 'message': 'An error occurred during login'}), 500

@app.route('/auth/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/login', methods=['GET'])
def admin_login():
    if 'admin' in session and session.get('admin'):
        return redirect(url_for('admin_panel'))
    return render_template('login.html', admin=True)

@app.route('/admin', methods=['GET'])
@admin_required
def admin_panel():
    load_users()
    return render_template('admin.html')

@app.route('/admin/users', methods=['GET'])
@admin_required
def get_users():
    try:
        users = load_users()
        users_list = []

        for username, user_data in users.items():
            try:
                expires_at = datetime.fromisoformat(user_data['expires_at'])
                created_at = datetime.fromisoformat(user_data['created_at'])
                now = datetime.now()

                days_left = (expires_at - now).days

                if expires_at < now:
                    days_left = (expires_at.date() - now.date()).days
            except Exception as e:
                print(f"Error processing user {username}: {e}")
                expires_at = datetime.now()
                created_at = datetime.now()
                days_left = -1

            users_list.append({
                'username': username,
                'created_at': user_data['created_at'],
                'expires_at': user_data['expires_at'],
                'status': user_data.get('status', 'active'),
                'days_left': days_left
            })

        users_list.sort(key=lambda x: x['username'])

        return jsonify({'status': 'success', 'users': users_list})
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/users', methods=['POST'])
@admin_required
def create_user():
    try:
        load_users()
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        expiry_days = int(data.get('expiry_days', 30))
        status = data.get('status', 'active')

        if not username:
            return jsonify({'status': 'error', 'message': 'Username is required'}), 400

        if not password:
            return jsonify({'status': 'error', 'message': 'Password is required'}), 400

        if expiry_days < 1 or expiry_days > 365:
            return jsonify({'status': 'error', 'message': 'Expiry days must be between 1 and 365'}), 400

        users = load_users()

        if username in users:
            return jsonify({'status': 'error', 'message': 'Username already exists'}), 400

        now = datetime.now()
        expires_at = now + timedelta(days=expiry_days)

        users[username] = {
            'password': generate_password_hash(password),
            'created_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'status': status
        }

        save_users(users)
        return jsonify({'status': 'success', 'message': 'User created successfully'})

    except Exception as e:
        print(f"Create user error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/users/<username>', methods=['PUT'])
@admin_required
def update_user(username):
    try:
        data = request.get_json()
        users = load_users()

        if username not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        if data.get('password'):
            users[username]['password'] = generate_password_hash(data['password'])

        if 'expiry_days' in data:
            expiry_days = int(data['expiry_days'])
            if expiry_days < 1 or expiry_days > 365:
                return jsonify({'status': 'error', 'message': 'Expiry days must be between 1 and 365'}), 400

            now = datetime.now()
            expires_at = now + timedelta(days=expiry_days)
            users[username]['expires_at'] = expires_at.isoformat()

        if 'status' in data:
            users[username]['status'] = data['status']

        save_users(users)
        return jsonify({'status': 'success', 'message': 'User updated successfully'})

    except Exception as e:
        print(f"Update user error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    try:
        users = load_users()

        if username not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        if username == ADMIN_USERNAME:
            return jsonify({'status': 'error', 'message': 'Cannot delete admin user'}), 400

        del users[username]
        save_users(users)
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})

    except Exception as e:
        print(f"Delete user error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/', methods=['GET'])
@login_required
def index():
    try:
        with open('emotes.json', 'r') as f:
            emotes = json.load(f)

        return render_template('index.html', emotes=emotes)
    except FileNotFoundError:
        print("ERROR: emotes.json file not found in the root directory.")
        return "ERROR: emotes.json file not found.", 500
    except Exception as e:
        print(f"An error occurred loading index.html: {e}")
        import traceback
        traceback.print_exc()
        return "An internal server error occurred.", 500

@app.route('/test_image/<filename>')
def test_image(filename):
    from flask import send_from_directory
    try:
        return send_from_directory(os.path.join(app.static_folder, 'images'), filename)
    except Exception as e:
        return f"Error loading image: {str(e)}", 404

@app.route('/send_emote', methods=['POST'])
@login_required
def send_emote():
    global LOOP

    if LOOP is None:
        return jsonify({
            "status": "error",
            "message": "Error: Bot system is not initialized. Please wait or restart."
        }), 503

    try:
        data = request.get_json()
        team_code = data.get('team_code')
        emote_id_str = data.get('emote_id')
        uids_str = data.get('uids', [])
        server = data.get('server', 'india').lower()

        if not all([team_code, emote_id_str, uids_str]):
            return jsonify({'message': 'Error: Missing team_code, emote_id, or UIDs'}), 400

        if server not in ['india', 'bangladesh']:
            return jsonify({'message': 'Error: Invalid server. Use "india" or "bangladesh"'}), 400

        target_uids_int = [int(uid) for uid in uids_str]
        emote_id_int = int(emote_id_str)

    except (ValueError, TypeError) as e:
        return jsonify({"status": "error", "message": f"Invalid data format: {e}"}), 400

    bot_manager = bot_managers.get(server)
    if not bot_manager:
        return jsonify({
            "status": "error",
            "message": f"Error: Server '{server}' is not configured."
        }), 503

    assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
    if not assigned_bot:
        return jsonify({
            "status": "error",
            "message": "Error: No bots available. Please configure bot credentials."
        }), 503

    if not assigned_bot.is_connected or not assigned_bot.online_writer or not assigned_bot.whisper_writer:
        return jsonify({
            "status": "error",
            "message": f"Error: Bot {assigned_bot.bot_id} is not connected yet. Please wait a moment."
        }), 503

    try:
        future = asyncio.run_coroutine_threadsafe(
            perform_emote_sequence(target_uids_int, emote_id_int, str(team_code), assigned_bot),
            LOOP
        )
        future.result(timeout=5)

        return jsonify({
            'status': 'success',
            'message': f'Emote request sent successfully for UIDs: {", ".join(uids_str)} using Bot {assigned_bot.bot_id} on {server.upper()} server!'
        })

    except asyncio.TimeoutError:
         return jsonify({
            "status": "error",
            "message": "Error: Operation timed out. The game server might be unresponsive or the team code was invalid."
        }), 500
    except Exception as e:
        print(f"Error in send_emote logic: {e}")
        return jsonify({
            "status": "error",
            "message": f"An internal error occurred during the emote operation: {str(e)}"
        }), 500

@app.route('/join', methods=['GET'])
@login_required
def join_and_emote_api():
    global LOOP

    target_uids_str = [request.args.get(f'uid{i}') for i in range(1, 6) if request.args.get(f'uid{i}')]
    emote_id_str = request.args.get('emote_id')
    team_code = request.args.get('tc')
    server = request.args.get('server', 'india').lower()

    if not target_uids_str or not emote_id_str or not team_code:
        return jsonify({"status": "error", "message": "Error: 'uid1', 'emote_id', and 'tc' are required parameters."}), 400

    if LOOP is None:
        return jsonify({"status": "error", "message": "Error: Bot system is not initialized."}), 503

    if server not in ['india', 'bangladesh']:
        return jsonify({"status": "error", "message": "Error: Invalid server. Use 'india' or 'bangladesh'."}), 400

    try:
        target_uids_int = [int(uid) for uid in target_uids_str]
        emote_id = int(emote_id_str)
    except ValueError:
        return jsonify({"status": "error", "message": "Error: UIDs and Emote ID must be numbers."}), 400

    bot_manager = bot_managers.get(server)
    if not bot_manager:
        return jsonify({
            "status": "error",
            "message": f"Error: Server '{server}' is not configured."
        }), 503

    assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
    if not assigned_bot:
        return jsonify({
            "status": "error",
            "message": "Error: No bots available. Please configure bot credentials."
        }), 503

    if not assigned_bot.is_connected or not assigned_bot.online_writer or not assigned_bot.whisper_writer:
        return jsonify({
            "status": "error",
            "message": f"Error: Bot {assigned_bot.bot_id} is not connected yet. Please wait a moment."
        }), 503

    try:
        future = asyncio.run_coroutine_threadsafe(
            perform_emote_sequence(target_uids_int, emote_id, str(team_code), assigned_bot),
            LOOP
        )
        future.result(timeout=30)

        return jsonify({
            "status": "success",
            "message": f"Successfully sent emote command for UIDs: {', '.join(target_uids_str)} using Bot {assigned_bot.bot_id} on {server.upper()} server."
        }), 200

    except asyncio.TimeoutError:
         return jsonify({"status": "error", "message": "Error: Operation timed out."}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"}), 500


async def execute_lag_command(team_code, duration, bot_instance):
    overall_start_time = time.time()
    total_packets = 0
    consecutive_errors = 0
    max_errors = 5

    while time.time() - overall_start_time < duration:
        try:
            if not bot_instance.online_writer or bot_instance.online_writer.is_closing():
                consecutive_errors += 1
                if consecutive_errors >= max_errors:
                    print(f"[Lag] Bot {bot_instance.bot_id} disconnected, stopping lag")
                    break
                await asyncio.sleep(0.1)
                continue

            consecutive_errors = 0

            join_packet = await GenJoinSquadsPacket(team_code, bot_instance.key, bot_instance.iv, bot_instance.region)
            bot_instance.online_writer.write(join_packet)
            await bot_instance.online_writer.drain()
            await asyncio.sleep(0.01)

            leave_packet = await ExiT(None, bot_instance.key, bot_instance.iv, bot_instance.region)
            bot_instance.online_writer.write(leave_packet)
            await bot_instance.online_writer.drain()
            await asyncio.sleep(0.01)
            total_packets += 1
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as conn_error:
            consecutive_errors += 1
            if consecutive_errors >= max_errors:
                print(f"[Lag] Connection error: {conn_error}, stopping after {max_errors} errors")
                bot_instance.online_writer = None
                break
            await asyncio.sleep(0.05)
        except AttributeError as attr_error:
            consecutive_errors += 1
            if consecutive_errors >= max_errors:
                print(f"[Lag] Writer error: {attr_error}, stopping")
                bot_instance.online_writer = None
                break
            await asyncio.sleep(0.05)
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= max_errors:
                print(f"Error in lag loop: {e}, stopping after {max_errors} errors")
                break
            await asyncio.sleep(0.05)

    return {"status": "success", "message": f"Sent {total_packets} packets in {duration}s"}

async def execute_attack_command(team_code, bot_instance):
    start_time = time.time()
    start_packet = await FS(bot_instance.key, bot_instance.iv, bot_instance.region)
    leave_packet = await ExiT(None, bot_instance.key, bot_instance.iv, bot_instance.region)
    consecutive_errors = 0
    max_errors = 5

    while time.time() - start_time < 45:
        try:
            if not bot_instance.online_writer or bot_instance.online_writer.is_closing():
                consecutive_errors += 1
                if consecutive_errors >= max_errors:
                    print(f"[Attack] Bot {bot_instance.bot_id} disconnected, stopping attack")
                    break
                await asyncio.sleep(0.1)
                continue

            consecutive_errors = 0

            join_packet = await GenJoinSquadsPacket(team_code, bot_instance.key, bot_instance.iv, bot_instance.region)
            bot_instance.online_writer.write(join_packet)
            await bot_instance.online_writer.drain()
            bot_instance.online_writer.write(start_packet)
            await bot_instance.online_writer.drain()
            bot_instance.online_writer.write(leave_packet)
            await bot_instance.online_writer.drain()
            await asyncio.sleep(0.15)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as conn_error:
            consecutive_errors += 1
            if consecutive_errors >= max_errors:
                print(f"[Attack] Connection error: {conn_error}, stopping after {max_errors} errors")
                bot_instance.online_writer = None
                break
            await asyncio.sleep(0.05)
        except AttributeError as attr_error:
            consecutive_errors += 1
            if consecutive_errors >= max_errors:
                print(f"[Attack] Writer error: {attr_error}, stopping")
                bot_instance.online_writer = None
                break
            await asyncio.sleep(0.05)
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= max_errors:
                print(f"Error in attack loop: {e}, stopping after {max_errors} errors")
                break
            await asyncio.sleep(0.05)

    return {"status": "success", "message": "Attack completed"}

async def execute_start_command(team_code, spam_count, bot_instance):
    try:
        if not bot_instance.online_writer or bot_instance.online_writer.is_closing():
            return {"status": "error", "message": "Bot not connected"}

        try:
            join_packet = await GenJoinSquadsPacket(team_code, bot_instance.key, bot_instance.iv, bot_instance.region)
            bot_instance.online_writer.write(join_packet)
            await bot_instance.online_writer.drain()
            await asyncio.sleep(2)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            bot_instance.online_writer = None
            return {"status": "error", "message": f"Connection error during join: {str(e)}"}

        start_packet = await FS(bot_instance.key, bot_instance.iv, bot_instance.region)
        sent_count = 0
        for _ in range(spam_count):
            if not bot_instance.online_writer or bot_instance.online_writer.is_closing():
                break
            try:
                bot_instance.online_writer.write(start_packet)
                await bot_instance.online_writer.drain()
                sent_count += 1
                await asyncio.sleep(0.2)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                bot_instance.online_writer = None
                break
            except AttributeError:
                bot_instance.online_writer = None
                break

        if bot_instance.online_writer and not bot_instance.online_writer.is_closing():
            try:
                leave_packet = await ExiT(None, bot_instance.key, bot_instance.iv, bot_instance.region)
                bot_instance.online_writer.write(leave_packet)
                await bot_instance.online_writer.drain()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                bot_instance.online_writer = None

        return {"status": "success", "message": f"Force start done ({sent_count}/{spam_count} times)"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

async def execute_teamcode_command(team_code, bot_instance):
    try:
        if not bot_instance.online_writer or bot_instance.online_writer.is_closing():
            return {"status": "error", "message": "Bot not connected"}

        try:
            join_packet = await GenJoinSquadsPacket(team_code, bot_instance.key, bot_instance.iv, bot_instance.region)
            bot_instance.online_writer.write(join_packet)
            await bot_instance.online_writer.drain()
            return {"status": "success", "message": f"Joining team {team_code}..."}
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            bot_instance.online_writer = None
            bot_instance.is_connected = False
            return {"status": "error", "message": f"Connection error: {str(e)}"}
        except AttributeError as e:
            bot_instance.online_writer = None
            bot_instance.is_connected = False
            return {"status": "error", "message": f"Writer error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

async def execute_solo_command(bot_instance):
    try:
        if not bot_instance.online_writer or bot_instance.online_writer.is_closing():
            return {"status": "error", "message": "Bot not connected"}

        try:
            leave_packet = await ExiT(None, bot_instance.key, bot_instance.iv, bot_instance.region)
            bot_instance.online_writer.write(leave_packet)
            await bot_instance.online_writer.drain()
            return {"status": "success", "message": "Left squad successfully"}
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
            bot_instance.online_writer = None
            bot_instance.is_connected = False
            return {"status": "error", "message": f"Connection error: {str(e)}"}
        except AttributeError as e:
            bot_instance.online_writer = None
            bot_instance.is_connected = False
            return {"status": "error", "message": f"Writer error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@app.route('/lag', methods=['POST'])
@login_required
def lag_api():
    global LOOP

    if LOOP is None:
        return jsonify({"status": "error", "message": "Bot system not initialized"}), 503

    try:
        data = request.get_json()
        team_code = data.get('team_code')
        server = data.get('server', 'india').lower()
        duration = int(data.get('duration', 10))

        if not team_code:
            return jsonify({"status": "error", "message": "Team code required"}), 400

        if duration < 2 or duration > 60:
            duration = 10

        bot_manager = bot_managers.get(server)
        if not bot_manager:
            return jsonify({"status": "error", "message": f"Server '{server}' not configured"}), 503

        assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
        if not assigned_bot or not assigned_bot.is_connected:
            return jsonify({"status": "error", "message": "Bot not available or not connected"}), 503

        future = asyncio.run_coroutine_threadsafe(
            execute_lag_command(team_code, duration, assigned_bot), LOOP
        )
        result = future.result(timeout=duration + 5)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/attack', methods=['POST'])
@login_required
def attack_api():
    global LOOP

    if LOOP is None:
        return jsonify({"status": "error", "message": "Bot system not initialized"}), 503

    try:
        data = request.get_json()
        team_code = data.get('team_code')
        server = data.get('server', 'india').lower()

        if not team_code:
            return jsonify({"status": "error", "message": "Team code required"}), 400

        bot_manager = bot_managers.get(server)
        if not bot_manager:
            return jsonify({"status": "error", "message": f"Server '{server}' not configured"}), 503

        assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
        if not assigned_bot or not assigned_bot.is_connected:
            return jsonify({"status": "error", "message": "Bot not available or not connected"}), 503

        future = asyncio.run_coroutine_threadsafe(
            execute_attack_command(team_code, assigned_bot), LOOP
        )
        result = future.result(timeout=50)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/start', methods=['POST'])
@login_required
def start_api():
    global LOOP

    if LOOP is None:
        return jsonify({"status": "error", "message": "Bot system not initialized"}), 503

    try:
        data = request.get_json()
        team_code = data.get('team_code')
        server = data.get('server', 'india').lower()
        spam_count = int(data.get('count', 20))

        if not team_code:
            return jsonify({"status": "error", "message": "Team code required"}), 400

        if spam_count > 50:
            spam_count = 50

        bot_manager = bot_managers.get(server)
        if not bot_manager:
            return jsonify({"status": "error", "message": f"Server '{server}' not configured"}), 503

        assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
        if not assigned_bot or not assigned_bot.is_connected:
            return jsonify({"status": "error", "message": "Bot not available or not connected"}), 503

        future = asyncio.run_coroutine_threadsafe(
            execute_start_command(team_code, spam_count, assigned_bot), LOOP
        )
        result = future.result(timeout=30)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/teamcode', methods=['POST'])
@login_required
def teamcode_api():
    global LOOP

    if LOOP is None:
        return jsonify({"status": "error", "message": "Bot system not initialized"}), 503

    try:
        data = request.get_json()
        team_code = data.get('team_code')
        server = data.get('server', 'india').lower()

        if not team_code:
            return jsonify({"status": "error", "message": "Team code required"}), 400

        bot_manager = bot_managers.get(server)
        if not bot_manager:
            return jsonify({"status": "error", "message": f"Server '{server}' not configured"}), 503

        assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
        if not assigned_bot or not assigned_bot.is_connected:
            return jsonify({"status": "error", "message": "Bot not available or not connected"}), 503

        future = asyncio.run_coroutine_threadsafe(
            execute_teamcode_command(team_code, assigned_bot), LOOP
        )
        result = future.result(timeout=10)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/solo', methods=['POST'])
@login_required
def solo_api():
    global LOOP

    if LOOP is None:
        return jsonify({"status": "error", "message": "Bot system not initialized"}), 503

    try:
        data = request.get_json()
        server = data.get('server', 'india').lower()
        team_code = data.get('team_code', '')

        bot_manager = bot_managers.get(server)
        if not bot_manager:
            return jsonify({"status": "error", "message": f"Server '{server}' not configured"}), 503

        if team_code:
            assigned_bot = bot_manager.get_or_assign_bot(str(team_code))
        else:
            assigned_bot = bot_manager.bot_instances[0] if bot_manager.bot_instances else None

        if not assigned_bot or not assigned_bot.is_connected:
            return jsonify({"status": "error", "message": "Bot not available or not connected"}), 503

        future = asyncio.run_coroutine_threadsafe(
            execute_solo_command(assigned_bot), LOOP
        )
        result = future.result(timeout=10)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/ai', methods=['POST'])
@login_required
def ai_api():
    try:
        data = request.get_json()
        question = data.get('question', '').strip()

        if not question:
            return jsonify({"status": "error", "message": "Question required"}), 400

        ai_response = talk_with_ai(question)
        return jsonify({"status": "success", "message": ai_response})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/status', methods=['GET'])
def status_api():
    try:
        server = request.args.get('server', 'all').lower()

        status_data = {
            "status": "success",
            "servers": {}
        }

        if server == 'all':
            for server_name, bot_manager in bot_managers.items():
                bots_status = []
                for bot in bot_manager.bot_instances:
                    bots_status.append({
                        "bot_id": bot.bot_id,
                        "uid": bot.uid[:10] + "..." if len(bot.uid) > 10 else bot.uid,
                        "is_connected": bot.is_connected,
                        "has_chat_writer": bot.whisper_writer is not None,
                        "has_online_writer": bot.online_writer is not None,
                        "region": bot.region if bot.region else "Unknown"
                    })
                status_data["servers"][server_name] = {
                    "total_bots": len(bot_manager.bot_instances),
                    "connected_bots": sum(1 for bot in bot_manager.bot_instances if bot.is_connected),
                    "bots": bots_status
                }
        else:
            bot_manager = bot_managers.get(server)
            if not bot_manager:
                return jsonify({"status": "error", "message": f"Server '{server}' not found"}), 404

            bots_status = []
            for bot in bot_manager.bot_instances:
                bots_status.append({
                    "bot_id": bot.bot_id,
                    "uid": bot.uid[:10] + "..." if len(bot.uid) > 10 else bot.uid,
                    "is_connected": bot.is_connected,
                    "has_chat_writer": bot.whisper_writer is not None,
                    "has_online_writer": bot.online_writer is not None,
                    "region": bot.region if bot.region else "Unknown"
                })
            status_data["servers"][server] = {
                "total_bots": len(bot_manager.bot_instances),
                "connected_bots": sum(1 for bot in bot_manager.bot_instances if bot.is_connected),
                "bots": bots_status
            }

        return jsonify(status_data)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


async def MaiiiinE_bot(bot_instance):
    global LOOP

    if LOOP is None:
        LOOP = asyncio.get_running_loop()

    Uid = bot_instance.uid
    Pw = bot_instance.password

    print(f"[Bot {bot_instance.bot_id}] Starting authentication...")
    print(f"[Bot {bot_instance.bot_id}] UID: {Uid[:10]}...")

    try:
        stagger_delay = random.uniform(0.5, 2.0)
        await asyncio.sleep(stagger_delay)

        open_id , access_token = await GeNeRaTeAccEss(Uid , Pw, retry_count=3, retry_delay=2.0)
        if not open_id or not access_token:
            print(f"[Bot {bot_instance.bot_id}] ❌ ERROR - Authentication failed after retries")
            print(f"[Bot {bot_instance.bot_id}] UID: {Uid[:10]}... | Please check credentials in BOT_CREDENTIALS")
            print(f"[Bot {bot_instance.bot_id}] Possible issues:")
            print(f"  - UID or password is incorrect")
            print(f"  - Account is banned or suspended")
            print(f"  - Network connection issue")
            print(f"  - Rate limiting (too many requests)")
            raise ValueError("Invalid account credentials")

        print(f"[Bot {bot_instance.bot_id}] ✓ Authentication successful, getting login data...")
    except ValueError:
        raise
    except Exception as auth_error:
        print(f"[Bot {bot_instance.bot_id}] ❌ Authentication exception: {auth_error}")
        raise ValueError("Authentication failed")

    try:
        PyL = await EncRypTMajoRLoGin(open_id , access_token)
        MajoRLoGinResPonsE = await MajorLogin(PyL)
        if not MajoRLoGinResPonsE:
            print(f"[Bot {bot_instance.bot_id}] ❌ ERROR - Target Account => Banned / Not Registered!")
            print(f"[Bot {bot_instance.bot_id}] Please verify the account is active and not banned")
            return None
        print(f"[Bot {bot_instance.bot_id}] ✓ Login response received")
    except Exception as login_error:
        print(f"[Bot {bot_instance.bot_id}] ❌ Login failed: {login_error}")
        return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(f"[Bot {bot_instance.bot_id}] Login URL: {UrL}")
    bot_instance.region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    bot_instance.key = MajoRLoGinauTh.key
    bot_instance.iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    try:
        LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
        if not LoGinDaTa:
            print(f"[Bot {bot_instance.bot_id}] ❌ ERROR - Failed to get ports from login data!")
            print(f"[Bot {bot_instance.bot_id}] This might indicate a server issue or invalid token")
            return None
        print(f"[Bot {bot_instance.bot_id}] ✓ Login data retrieved successfully")
    except Exception as login_data_error:
        print(f"[Bot {bot_instance.bot_id}] ❌ ERROR getting login data: {login_data_error}")
        return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName

    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , bot_instance.key , bot_instance.iv)
    ready_event = asyncio.Event()

    max_connection_attempts = 3
    connection_delay = 1.0

    for attempt in range(1, max_connection_attempts + 1):
        try:
            print(f"[Bot {bot_instance.bot_id}] Connecting to chat server... (Attempt {attempt}/{max_connection_attempts})")
            task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , bot_instance.key , bot_instance.iv , LoGinDaTaUncRypTinG , ready_event , bot_instance.region, bot_instance))

            try:
                await asyncio.wait_for(ready_event.wait(), timeout=15.0)
                await asyncio.sleep(1.0)
                print(f"[Bot {bot_instance.bot_id}] ✓ Chat server connected")
            except asyncio.TimeoutError:
                print(f"[Bot {bot_instance.bot_id}] ⚠ Chat connection timeout, retrying...")
                try:
                    task1.cancel()
                    await asyncio.sleep(0.2)
                except:
                    pass

                if bot_instance.whisper_writer:
                    try:
                        bot_instance.whisper_writer.close()
                        await asyncio.wait_for(bot_instance.whisper_writer.wait_closed(), timeout=1.0)
                    except:
                        pass
                    bot_instance.whisper_writer = None

                await asyncio.sleep(connection_delay)
                connection_delay *= 1.5
                ready_event = asyncio.Event()
                continue

            print(f"[Bot {bot_instance.bot_id}] Connecting to online server... (Attempt {attempt}/{max_connection_attempts})")
            task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , bot_instance.key , bot_instance.iv , AutHToKen, bot_instance))
            await asyncio.sleep(1.5)

            max_wait = 15
            wait_time = 0
            connection_verified = False

            while wait_time < max_wait:
                if bot_instance.whisper_writer and bot_instance.online_writer:
                    try:
                        chat_valid = (bot_instance.whisper_writer is not None and
                                     not bot_instance.whisper_writer.is_closing())
                        online_valid = (bot_instance.online_writer is not None and
                                       not bot_instance.online_writer.is_closing())

                        if chat_valid and online_valid:
                            try:
                                bot_instance.whisper_writer.get_extra_info('sockname')
                                bot_instance.online_writer.get_extra_info('sockname')
                            except (AttributeError, OSError):
                                pass

                            bot_instance.is_connected = True
                            connection_verified = True
                            print(f"[Bot {bot_instance.bot_id}] ✓ Connected! Bot Name: {acc_name} | Target UID: {TarGeT}")
                            break
                    except (AttributeError, OSError, RuntimeError) as check_error:
                        await asyncio.sleep(0.2)
                        continue

                await asyncio.sleep(0.5)
                wait_time += 0.5

            if connection_verified:
                await asyncio.gather(task1, task2, return_exceptions=True)
                return

            print(f"[Bot {bot_instance.bot_id}] ⚠ Connection verification failed, retrying...")
            print(f"[Bot {bot_instance.bot_id}] Chat writer: {'✓' if bot_instance.whisper_writer else '✗'}, Online writer: {'✓' if bot_instance.online_writer else '✗'}")

            try:
                task1.cancel()
                task2.cancel()
                await asyncio.sleep(0.2)
            except:
                pass

            if bot_instance.whisper_writer:
                try:
                    bot_instance.whisper_writer.close()
                    await asyncio.wait_for(bot_instance.whisper_writer.wait_closed(), timeout=2.0)
                except:
                    pass
                bot_instance.whisper_writer = None

            if bot_instance.online_writer:
                try:
                    bot_instance.online_writer.close()
                    await asyncio.wait_for(bot_instance.online_writer.wait_closed(), timeout=2.0)
                except:
                    pass
                bot_instance.online_writer = None

            bot_instance.is_connected = False

            if attempt < max_connection_attempts:
                await asyncio.sleep(connection_delay)
                connection_delay *= 1.5
                ready_event = asyncio.Event()
            else:
                print(f"[Bot {bot_instance.bot_id}] ❌ Failed to connect after {max_connection_attempts} attempts")
                raise ConnectionError(f"Failed to establish connections after {max_connection_attempts} attempts")

        except Exception as conn_error:
            if attempt < max_connection_attempts:
                print(f"[Bot {bot_instance.bot_id}] ⚠ Connection error: {conn_error}, retrying in {connection_delay:.1f}s...")
                await asyncio.sleep(connection_delay)
                connection_delay *= 1.5
                ready_event = asyncio.Event()
            else:
                print(f"[Bot {bot_instance.bot_id}] ❌ Connection failed after {max_connection_attempts} attempts: {conn_error}")
                raise

async def MaiiiinE():
    global LOOP, key, iv, region, whisper_writer, online_writer

    LOOP = asyncio.get_running_loop()

    Uid , Pw = '4217619872' , 'B152DFAE97F244855483BAD194F44CA429B00197C0B155D8D07862B1FC095E6D'

    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: print("ErroR - InvaLid AccounT") ; return None

    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") ; return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin Da Ta !") ; return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName

    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()

    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event ,region))
    await ready_event.wait()
    await asyncio.sleep(0.1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen))

    def run_flask():
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        app.logger.setLevel(logging.ERROR)
    
    if __name__ == '__main__':
     app.run(debug=False)

    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    os.system('clear')
    print(render('CLOUD ENGINE', colors=['white', 'green'], align='center'))
    print('')
    print(f" - BoT STarTinG And OnLine on TarGeT : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")
    print(f" - Web UI and API started on http://0.0.0.0:30151/")
    print(f" - API Example: http://<YOUR_IP>:30151/join?uid1=<UID>&emote_id=<ID>&tc=<CODE>")
    print(f" - Subscribe > CLOUD ENGINE | Gaming ! (:")
    await asyncio.gather(task1, task2)

async def StarTinG_multi():
    global LOOP

    total_bots = 0
    for server_name, credentials in BOT_CREDENTIALS.items():
        if not credentials:
            print(f"[{server_name.upper()}] No bot credentials configured!")
            continue

        bot_manager = bot_managers[server_name]
        bot_id_counter = 1

        for cred in credentials:
            uid = cred.get('uid', '')
            password = cred.get('password', '')

            if uid.upper() in ['UIDDFFDFDFD', 'YOUR_UID', ''] or password.upper() in ['PASSWORDS', 'YOUR_PASSWORD', '']:
                print(f"[BotManager-{server_name.upper()}] ⚠ Skipping placeholder credentials for Bot {bot_id_counter}")
                continue

            if 'OFFLINE' in password.upper():
                print(f"[BotManager-{server_name.upper()}] ⚠ WARNING: Bot {bot_id_counter} has 'OFFLINE' in password - this may be a placeholder!")
                print(f"[BotManager-{server_name.upper()}]    Please verify credentials are correct for UID: {uid[:10]}...")

            bot_instance = BotInstance(bot_id_counter, uid, password)
            bot_manager.bot_instances.append(bot_instance)
            print(f"[BotManager-{server_name.upper()}] ✓ Initialized Bot {bot_instance.bot_id} with UID: {uid[:10]}...")
            bot_id_counter += 1

        print(f"[BotManager-{server_name.upper()}] Total bots initialized: {len(bot_manager.bot_instances)}")
        total_bots += len(bot_manager.bot_instances)

    print(f"\n[Total] All servers: {total_bots} bots initialized")

    # 🚀 START FLASK WEBSITE
    import threading
    
    def start_flask():
      print("🌐 STARTING FLASK WEBSITE ON PORT 5000...")
      app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()
    print("✅ FLASK WEBSITE STARTED!")

    os.system('clear')
    print(render('CLOUD ENGINE', colors=['white', 'green'], align='center'))
    print('')
    print(f"[Multi-Bot System] Starting {total_bots} bots across all servers...")
    print(f" - Web UI and API started on http://0.0.0.0:30151/")
    print(f" - Server Selection: India / Bangladesh")
    print(f" - Team codes will be automatically assigned to different bots")
    print(f" - Same team code = Same bot | Different team code = Different bot")
    print('')

    async def bot_worker(bot, server_name):
        consecutive_auth_failures = 0
        max_auth_failures = 5
        retry_delay = 10.0

        while True:
            try:
                await asyncio.wait_for(MaiiiinE_bot(bot), timeout=7 * 60 * 60)
                consecutive_auth_failures = 0
                retry_delay = 10.0
            except ValueError as ve:
                consecutive_auth_failures += 1
                if consecutive_auth_failures >= max_auth_failures:
                    print(f"[Bot-{server_name.upper()} {bot.bot_id}] ❌ Authentication failed {max_auth_failures} times. Stopping bot.")
                    print(f"[Bot-{server_name.upper()} {bot.bot_id}] Please check credentials in BOT_CREDENTIALS configuration.")
                    print(f"[Bot-{server_name.upper()} {bot.bot_id}] UID: {bot.uid[:10]}...")
                    break

                wait_time = min(retry_delay, 180.0)
                print(f"[Bot-{server_name.upper()} {bot.bot_id}] ⚠ Authentication failed ({consecutive_auth_failures}/{max_auth_failures})")
                print(f"[Bot-{server_name.upper()} {bot.bot_id}] Retrying in {wait_time:.0f} seconds... (Note: Auth function already retried 3 times)")
                bot.is_connected = False
                await asyncio.sleep(wait_time)
                retry_delay *= 2
            except asyncio.TimeoutError:
                print(f"[Bot-{server_name.upper()} {bot.bot_id}] ⚠ Token Expired! Restarting in 5 seconds...")
                bot.is_connected = False
                consecutive_auth_failures = 0
                retry_delay = 10.0
                await asyncio.sleep(5)
            except Exception as e:
                print(f"[Bot-{server_name.upper()} {bot.bot_id}] ⚠ Error: {e} => Restarting in 5 seconds...")
                bot.is_connected = False
                consecutive_auth_failures = 0
                retry_delay = 10.0
                await asyncio.sleep(5)

    bot_tasks = []
    for server_name, bot_manager in bot_managers.items():
        for bot in bot_manager.bot_instances:
            bot_tasks.append(asyncio.create_task(bot_worker(bot, server_name)))

    await asyncio.gather(*bot_tasks)

async def StarTinG():
    while True:
        try: await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed! Restarting...")
        except Exception as e: print(f"ErroR TcP - {e} => Restarting...")
# Add to your Flask app
# Add this RIGHT AFTER the app = Flask(...) line but BEFORE all other routes
# ===== DISCORD BOT API ENDPOINTS =====


# Add a test endpoint
@app.route('/api/test', methods=['GET'])
def test_api():
    return jsonify({'status': 'success', 'message': 'API is working!'})
    
    # Add this right before the if __name__ == '__main__': section
def run_flask():
    print("🌐 STARTING FLASK WEBSITE ON PORT 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    
# Then modify your if __name__ block:
if __name__ == '__main__':
    total_creds = sum(len(creds) for creds in BOT_CREDENTIALS.values())
    
    # 🚀 Start Flask FIRST
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    print("✅ FLASK WEBSITE STARTED on http://localhost:5000/")
    
    # Then start bots
    if total_creds > 1:
        print("[System] Multi-bot mode enabled with server support")
        asyncio.run(StarTinG_multi())
    elif total_creds == 1:
        print("[System] Single-bot mode (legacy)")
        asyncio.run(StarTinG())
    else:
        print("[System] ERROR: No bot credentials configured!")
