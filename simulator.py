import sys
import configparser
import base64
import requests

import log
import emv
from datetime import datetime
from emv import EMVReader
from base import BaseSimulator
from stress import StressSimulator
import helper

reader = EMVReader()

def try_read(timeout=5):
    max_count = (int)(timeout / 0.1)
    for _ in range(0,max_count):
        rv, rsp, rsplen = reader.read()
        if rv == False:
            continue

        log.debug(f"read:{rsp.hex()}")
        if rsp[0:1] == emv.ACK_BYTE:
            log.info("acked")
            continue

        txn_code, rsp_code = emv.parse_present_hdr(rsp[13:21])
        txn_code_str = txn_code.decode('utf8')
        rsp_code_str = rsp_code.decode('utf8')
        print(f'txn_code:{txn_code_str}, rsp_code:{rsp_code_str}')
        fields = emv.dec_fields(rsp[21:len(rsp)-2])
        
        for k, v in fields.items():
            tag = k
            taglen = v[0]
            value = v[1]
            try:
                log.info(f"{tag} {taglen:4d} str: {value.decode()}")
            except:
                log.info(f"{tag} {taglen:4d} hex: {value.hex()}")
        return fields

if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('config.ini')

    now = datetime.now()
    filename = 'SIM' + now.strftime('%y%m%d') + '.log'
    loglevel = config.get('Logging', 'logLevel', fallback='debug')
    log.init(filename, loglevel)

    portname = config.get('Ingenico', 'portName', fallback='COM1')
    reader.open(portname)

    argc = len(sys.argv)
    test = ""
    if argc > 1:
        test = sys.argv[1]
    if argc > 2:
        data = bytes.fromhex(sys.argv[2])

    if test == "tap":
        reader.transit_tap()
        try_read()
    elif test == "cancel":
        reader.cancel()
        try_read()
    elif test == "heartbeat":
        reader.heartbeat()
        try_read()
    elif test == "heartbeat-live":
        reader.heartbeat(0)
        try_read()
    elif test == "heartbeat-ver":
        reader.heartbeat(1)
        try_read()
    elif test == "heartbeat-key":
        reader.heartbeat(2)
        try_read()
    elif test == "download":
        reader.download()
        try_read()
    elif test == "reboot":
        reader.reboot()
        try_read()
    elif test == "reboot-only":
        reader.reboot(0)
        #try_read()
    elif test == "reboot-clean-buf":
        reader.reboot(1)
        #try_read()
    elif test == "reboot-clean-rej":
        reader.reboot(2)
        #try_read()
    elif test == "reboot-clean-all":
        reader.reboot(3)
        #try_read()
    elif test == "readsn":
        reader.read_bsam_sn()
        try_read()
    elif test == "sign":
        reader.tm_signature(data)
        try_read()
    elif test == "updatekeys":
        reader.update_keys(data)
        try_read()
    elif test == "req_key":

        eqp_sw_id = b""
        eqp_sn = b""
        pto = config.get('KLD', 'pto', fallback='PTO')
        pto_id = str.encode(pto)
        env = b"Support"
        eqp_id = b""
        scd_sn = b""
        try:
            reader.read_bsam_sn()
            fields = try_read()
            tmp = fields['UL'][1]
            scd_sn = bytes(tmp)
        except:
            pass
        scd_type = b"SA"
        scd_id = b""
        ksn = b""
        try:
            reader.heartbeat(1)
            fields = try_read()
            tmp = fields['TI'][1]
            tmp = bytes.fromhex(tmp.decode()).decode()
            tmp = tmp.lstrip("0")
            scd_id = str.encode(tmp)

            tmp = fields['TR'][1]
            ksn = bytes(tmp)
        except:
            pass
        term_id = b""
        wk_keys = b"WK"
        emk_kcv = b""
        tkk_kcv = b""
        mac_kcv = b""
        ktrex_kcv = b""
        try:
            reader.heartbeat(2)
            fields = try_read()
            tmp = fields['UB'][1]
            emk_kcv = bytes(tmp)

            #tmp = fields['U7'][1]
            #tkk_kcv = bytes(tmp)

            #tmp = fields['UK'][1]
            #mac_kcv = bytes(tmp)
            
            tmp = config.get('KLD', 'ktrexKcv', fallback='E43CF3')
            ktrex_kcv = str.encode(tmp)
        except:
            pass

        req = dict()

        req[0x50] = eqp_sw_id
        req[0x58] = eqp_sn
        req[0x51] = pto_id
        req[0x52] = env
        req[0x53] = eqp_id
        req[0x54] = scd_sn
        req[0x55] = scd_type
        req[0x56] = scd_id
        req[0x59] = term_id
        req[0x40] = wk_keys
        req[0x41] = ksn
        req[0x42] = emk_kcv
        req[0x43] = tkk_kcv
        req[0x44] = mac_kcv
        req[0x45] = ktrex_kcv
        payload = helper.form_tlv(req)

        mac = bytearray([2]*32)
        try:
            reader.tm_signature(bytes(payload))
            fields = try_read()
            tmp = fields['UN'][1]
            mac = bytes.fromhex(tmp.decode())
        except:
            pass

        req[0x57] = mac
        #for k, v in req.items():
        #    try:
        #        print(f"{k:02x} str: {v.decode()}")
        #    except:
        #        print(f"{k:02x} hex: {v.hex()}")

        http_req = helper.form_tlv(req)
        content = base64.b64encode(bytes(http_req))
        print(content)

        host = config.get('KLD', 'host', fallback='127.0.0.1:5000')
        url = f"http://{host}/kld/scd/key"
        http_rsp = requests.post(url, data=content)
        print(http_rsp)

        buffer = base64.b64decode(http_rsp.content)
        rsp = helper.extract_tlv(buffer)
        for k, v in rsp.items():
            try:
                print(f"{k:02x} str: {v.decode()}")
            except:
                print(f"{k:02x} hex: {v.hex()}")

        print(rsp[0x32])
        reader.update_keys(bytes.fromhex(rsp[0x32][10:].decode()))
        try_read()


    elif test == "stress":
        sim = StressSimulator(reader, 3)
        sim.run()
    else:
        sim = BaseSimulator(reader)
        sim.run()

    reader.close()
