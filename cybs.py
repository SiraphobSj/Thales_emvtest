import log
import configparser
import base64
import hmac
import hashlib
import json
import requests
from datetime import datetime, timezone

GET_TAP_ENDPOINT = "/tms/v2/taps/"
#GET_TAP_ENDPOINT = "/cup/tms/v2/taps/"
SEND_TAP_ENDPOINT = "/tms/v2/taps/"
#SEND_TAP_ENDPOINT = "/cup/tms/v2/taps/"

class CybsClient:

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.read_host()
        self.read_mid1()
        self.read_mid2()

    def read_host(self):
        self.host = self.config.get('CyberSource', 'Host', fallback='127.0.0.1')

    def read_mid1(self):
        MerchantId = self.config.get('CyberSource', 'mId1MerchantId', fallback='MerchantId')
        key_id = self.config.get('CyberSource', 'mId1KeyId', fallback='keyid')
        key_secret = self.config.get('CyberSource', 'mId1KeySecret', fallback='keysecret')
        self.mid1 = [MerchantId, key_id, key_secret]

    def read_mid2(self):
        MerchantId = self.config.get('CyberSource', 'mId2MerchantId', fallback='MerchantId')
        key_id = self.config.get('CyberSource', 'mId2KeyId', fallback='keyid')
        key_secret = self.config.get('CyberSource', 'mId2KeySecret', fallback='keysecret')
        self.mid2 = [MerchantId, key_id, key_secret]

    def calc_digest(self, data):
        data_bytes = data.encode()
        sha = hashlib.sha256()
        sha.update(data_bytes)
        digest_bytes = sha.digest()
        digest_b64 = base64.b64encode(digest_bytes)
        return digest_b64.decode()

    def calc_sign(self, data, keysecret):
        secret_bytes = keysecret.encode()
        data_bytes = data.encode()
        secret_b64 = base64.b64decode(secret_bytes)
        digest_b64 = hmac.new(secret_b64, data_bytes, digestmod=hashlib.sha256).digest()
        digest_bytes = base64.b64encode(digest_b64)
        return digest_bytes.decode()
    
    def req_get(self, target, mid, keyid, keysecret):
        url = f"https://{self.host}{target}"
        #url = f"http://{self.host}{target}"
        log.info(f"req_get:{url}")

        date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %T GMT")
        #date_str = "Wed, 17 Jan 2024 08:57:29 GMT"

        data = f"host: {self.host}\n"
        #data = f"host: cgk2-hercules-cup-icl-ll-8443.ingress.malin.visa.com\n"
        data += f"date: {date_str}\n"
        data += f"request-target: get {target}\n"
        data += f"v-c-merchant-id: {mid}"
        log.debug(data)
        signature = self.calc_sign(data, keysecret)

        sign_blk = f"keyid=\"{keyid}\", "
        sign_blk += "algorithm=\"HmacSHA256\", "
        sign_blk += "headers=\"host date request-target v-c-merchant-id\", "
        sign_blk += f"signature=\"{signature}\""

        headers = {
            'host': self.host,
#            "host": "cgk2-hercules-cup-icl-ll-8443.ingress.malin.visa.com",
            "v-c-merchant-id": mid,
            "date": date_str,
            "signature": sign_blk
        }
        log.info(headers)

        rsp = requests.get(url, headers=headers)
        log.info(rsp)
        log.info(rsp.text)
    
    def req_post(self, target, mid, keyid, keysecret, content):
        url = f"https://{self.host}{target}"
        #url = f"http://{self.host}{target}"
        log.info(f"req_post:{url}")

        date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %T GMT")
        digest = self.calc_digest(content)

        data = f"host: {self.host}\n"
        #data = f"host: cgk2-hercules-cup-icl-ll-8443.ingress.malin.visa.com\n"
        data += f"date: {date_str}\n"
        data += f"request-target: post {target}\n"
        data += f"digest: SHA-256={digest}\n"
        data += f"v-c-merchant-id: {mid}"
        signature = self.calc_sign(data, keysecret)

        sign_blk = f"keyid=\"{keyid}\", "
        sign_blk += "algorithm=\"HmacSHA256\", "
        sign_blk += "headers=\"host date request-target digest v-c-merchant-id\", "
        sign_blk += f"signature=\"{signature}\""

        headers = {
            'host': self.host,
#            "host": "cgk2-hercules-cup-icl-ll-8443.ingress.malin.visa.com",
            'v-c-merchant-id': mid,
            'date': date_str,
            'digest': f"SHA-256={digest}",
            'signature': sign_blk,
            'Content-Type': "application/json",
            'Content-Length': str(len(content))
        }
        log.info(headers)
        log.info(content)

        try:
            rsp = requests.post(url, data=content, headers=headers, verify=True)
        except Exception as e:
            print(e)

        log.info(rsp)
        log.info(rsp.headers)
        log.info(rsp.content)

    def get_tap(self, corr_id):
        target = f"{GET_TAP_ENDPOINT}{corr_id}"
        MerchantId = self.mid2[0]
        keyid = self.mid2[1]
        keysecret = self.mid2[2]
        self.req_get(target, MerchantId, keyid, keysecret)

    def send_tap(self, span, corr_id, fluid_data):
        target = f"{SEND_TAP_ENDPOINT}"
        MerchantId = self.mid1[0]
        keyid = self.mid1[1]
        keysecret = self.mid1[2]

        content_json = {
            "id": corr_id, 
            "paymentInformation": {
                "card": {
                    "hash": span
                    }, 
                "fluidData": {
                    "descriptor": "4649443D454D562E5041594D454E542E415049",
                    "encoding": "Hex",
                    "value": fluid_data
                },
                }, 
            "processingInformation": {
                "industryDataType": "transit"
            }
        }
        content = json.dumps(content_json)
        self.req_post(target, MerchantId, keyid, keysecret, content)
