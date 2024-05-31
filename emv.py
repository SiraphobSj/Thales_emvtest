import serial
import threading
import time
import uuid
import log

ACK_BYTE = b'\x06'
STX_BYTE = b'\x02'
ETX_BYTE = b'\x03'

TRANSIT_TAP_TXN_CODE = "35"
CANCEL_TXN_CODE = "36"
HEARTBEAT_TXN_CODE = "37"
TMS_DOWNLOAD_TXN_CODE = "38"
CARD_DETECTED_TXN_CODE = "39"
READER_REBOOT_TXN_CODE = "40"
READ_BSAM_SN_TXN_CODE = "41"
TM_SIGNAUTRE_TXN_CODE = "42"
UPDATE_KEYS_TXN_CODE = "43"

def calc_lrc(buffer):
    lrc = 0
    for b in buffer:
        lrc ^= b
    return lrc

def dec2bcd(dec):
    tmp = str(dec)
    return int(tmp, 16)

def bcd2dec(bcd):
    tmp = f'{bcd:x}'
    return int(tmp)

def parse_trsport_hdr(buffer):
    if len(buffer) < 10:
        return
    hdr = buffer[0:2]
    dest = buffer[2:6]
    src = buffer[6:10]
    #log.debug(f"hdr:{hdr}")
    #log.debug(f"dest:{dest}")
    #log.debug(f"src:{src}")

def parse_present_hdr(buffer):
    if len(buffer) < 8:
        return
    fmt = buffer[0:1]
    ind = buffer[1:2]
    txn_code = buffer[2:4]
    rsp_code = buffer[4:6]
    more_ind = buffer[6:7]
    sep = buffer[7:8]
    #log.debug(f"fmt:{fmt}")
    #log.debug(f"ind:{ind}")
    #log.debug(f"txn_code:{txn_code}")
    #log.debug(f"rsp_code:{rsp_code}")
    #log.debug(f"more_ind:{more_ind}")
    #log.debug(f"sep:{sep}")
    return txn_code, rsp_code

def dec_fields(buffer):
    idx = 0
    #fields = []
    fields = dict()
    while idx < len(buffer):
        tag = buffer[idx:idx+2].decode()
        idx += 2
        taglen_bcd = int.from_bytes(buffer[idx:idx+2], 'big')
        taglen = bcd2dec(taglen_bcd)
        idx += 2
        value = buffer[idx:idx+taglen]
        idx += taglen
        idx += 1

        #tag_str = tag.decode('utf8')
        #value_str = value.decode('utf8')
        #log.debug(f"tag:{tag_str}, taglen:{taglen:4d}, value:{value_str}")
        #fields.append([tag, taglen, value])
        fields[tag] = [taglen, value]
    return fields

def enc_fields(fields):
    field_bytes = bytearray()
    for field in fields:
        if len(field) < 3:
            continue
        tag = field[0]
        taglen = field[1]
        value = field[2]
        field_bytes += tag
        field_bytes += dec2bcd(taglen).to_bytes(2, 'big')
        field_bytes += value
        field_bytes += b'\x1c'
    return field_bytes

class EMVReader():

    def __init__(self):
        self._lock = threading.Lock()
        self.ser = None

    def open(self, portname):
        try:
            self.ser = serial.Serial()
            self.ser.timeout = 0.1 # 100ms
            self.ser.port = portname
            self.ser.open()
            if self.ser.is_open:
                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()
            log.info(f"EMVReader.open: open {portname} success")
        except:
            log.info(f"EMVReader.open: open {portname} failure")
        return self.ser.is_open

    def close(self):
        with self._lock:
            self.ser.close()
        log.info("EMVReader.close")
        return (not self.ser.is_open)

    def transit_tap(self, corr_id=None):
        fields = []

        if corr_id == None:
            uuid_str = str(uuid.uuid4())
        else:
            uuid_str = corr_id
        uuid_bytes = bytearray(uuid_str.encode())

        #wait_pg_rsp = b'0' # T1
        #pg_rsp_timeout = b'0' # T2
        #solution_id = b'12345678' # T3
        #third_party_cert_nb = b'000987654321' # T4
        sensitive_tag = b'\x02\x01\x57' # T5
        non_sensitve_tag = \
            b'\x02\x01\x9a' + \
            b'\x02\x01\x9c' + \
            b'\x02\x02\x5f\x2a' + \
            b'\x02\x02\x9f\x1a' + \
            b'\x02\x02\x9f\x02' + \
            b'\x02\x02\x9f\x03' + \
            b'\x02\x02\x5f\x34' + \
            b'\x02\x02\x9f\x36' + \
            b'\x02\x01\x82' + \
            b'\x02\x01\x84' + \
            b'\x02\x01\x95' + \
            b'\x02\x02\x9f\x10' + \
            b'\x02\x02\x9f\x26' + \
            b'\x02\x02\x9f\x27' + \
            b'\x02\x02\x9f\x33' + \
            b'\x02\x02\x9f\x34' + \
            b'\x02\x02\x9f\x37' + \
            b'\x02\x02\x9f\x6e' # T6
        response_tag =  \
            b'\x02\x01\x4f' + \
            b'\x02\x02\x5f\x28' + \
            b'\x02\x02\x5f\x2a' + \
            b'\x02\x02\x5f\x34' + \
            b'\x02\x02\x5f\x24' + \
            b'\x02\x01\x50' + \
            b'\x02\x02\x96\xfe' + \
            b'\x02\x02\x9f\x67' + \
            b'\x02\x01\x42' + \
            b'\x02\x02\x9f\x0c' + \
            b'\x02\x02\x9f\x6c' + \
            b'\x02\x02\x9f\x6e' + \
            b'\x02\x02\x9f\x10'

        fields.append([b'T0', len(uuid_bytes), uuid_bytes])
        #fields.append([b'T1', len(wait_pg_rsp), wait_pg_rsp])
        #fields.append([b'T2', len(pg_rsp_timeout), pg_rsp_timeout])
        #fields.append([b'T3', len(solution_id), solution_id])
        #fields.append([b'T4', len(third_party_cert_nb), third_party_cert_nb])
        fields.append([b'T5', len(sensitive_tag), sensitive_tag])
        fields.append([b'T6', len(non_sensitve_tag), non_sensitve_tag])
        fields.append([b'T7', len(response_tag), response_tag])

        msg = self.form_command(TRANSIT_TAP_TXN_CODE, fields)
        self.write(msg, len(msg))
    def transit_tap(self, corr_id=None):
        fields = []

        if corr_id == None:
            uuid_str = str(uuid.uuid4())
        else:
            uuid_str = corr_id
        uuid_bytes = bytearray(uuid_str.encode())

        #wait_pg_rsp = b'0' # T1
        #pg_rsp_timeout = b'0' # T2
        #solution_id = b'12345678' # T3
        #third_party_cert_nb = b'000987654321' # T4
        sensitive_tag = b'\x02\x01\x57' # T5
        non_sensitve_tag = \
            b'\x02\x01\x9a' + \
            b'\x02\x01\x9c' + \
            b'\x02\x02\x5f\x2a' + \
            b'\x02\x02\x9f\x1a' + \
            b'\x02\x02\x9f\x02' + \
            b'\x02\x02\x9f\x03' + \
            b'\x02\x02\x5f\x34' + \
            b'\x02\x02\x9f\x36' + \
            b'\x02\x01\x82' + \
            b'\x02\x01\x84' + \
            b'\x02\x01\x95' + \
            b'\x02\x02\x9f\x10' + \
            b'\x02\x02\x9f\x26' + \
            b'\x02\x02\x9f\x27' + \
            b'\x02\x02\x9f\x33' + \
            b'\x02\x02\x9f\x34' + \
            b'\x02\x02\x9f\x37' + \
            b'\x02\x02\x9f\x6e' # T6
        response_tag =  \
            b'\x02\x01\x4f' + \
            b'\x02\x02\x5f\x28' + \
            b'\x02\x02\x5f\x2a' + \
            b'\x02\x02\x5f\x34' + \
            b'\x02\x02\x5f\x24' + \
            b'\x02\x01\x50' + \
            b'\x02\x02\x96\xfe' + \
            b'\x02\x02\x9f\x67' + \
            b'\x02\x01\x42' + \
            b'\x02\x02\x9f\x0c'

        fields.append([b'T0', len(uuid_bytes), uuid_bytes])
        #fields.append([b'T1', len(wait_pg_rsp), wait_pg_rsp])
        #fields.append([b'T2', len(pg_rsp_timeout), pg_rsp_timeout])
        #fields.append([b'T3', len(solution_id), solution_id])
        #fields.append([b'T4', len(third_party_cert_nb), third_party_cert_nb])
        fields.append([b'T5', len(sensitive_tag), sensitive_tag])
        fields.append([b'T6', len(non_sensitve_tag), non_sensitve_tag])
        fields.append([b'T7', len(response_tag), response_tag])

        msg = self.form_command(TRANSIT_TAP_TXN_CODE, fields)
        self.write(msg, len(msg))

    def cancel(self):
        msg = self.form_command(CANCEL_TXN_CODE)
        self.write(msg, len(msg))

    def heartbeat(self, req_type=None):
        fields = []

        if req_type != None:
            type_str = str(req_type)
            type_bytes = bytearray(type_str.encode())
            fields.append([b'TQ', len(type_bytes), type_bytes])

        msg = self.form_command(HEARTBEAT_TXN_CODE, fields)
        self.write(msg, len(msg))

    def download(self):
        msg = self.form_command(TMS_DOWNLOAD_TXN_CODE)
        self.write(msg, len(msg))

    def reboot(self, req_type=None):
        fields = []

        if req_type != None:
            type_str = str(req_type)
            type_bytes = bytearray(type_str.encode())
            fields.append([b'TP', len(type_bytes), type_bytes])

        msg = self.form_command(READER_REBOOT_TXN_CODE, fields)
        self.write(msg, len(msg))

    def read_bsam_sn(self):
        msg = self.form_command(READ_BSAM_SN_TXN_CODE)
        self.write(msg, len(msg))

    def tm_signature(self, data):
        print(data)
        fields = []

        # TODO: if data is hexstring or bytes
        fields.append([b'UM', len(data), data])

        msg = self.form_command(TM_SIGNAUTRE_TXN_CODE, fields)
        self.write(msg, len(msg))

    def update_keys(self, data):
        fields = []

        # TODO: if data is hexstring or bytes
        fields.append([b'UO', len(data), data])

        msg = self.form_command(UPDATE_KEYS_TXN_CODE, fields)
        self.write(msg, len(msg))

    def ack(self):
        log.debug('ACK')
        with self._lock:
            self.ser.write(ACK_BYTE)

    def read(self):
        step = 0
        rsplen_bytes = bytearray()
        rsp = bytearray()
        rsplen = 0

        while True:
            with self._lock:
                b = self.ser.read(1)
                rsp += b
            if len(b) == 0:
                break
            if step == 0:
                if b == ACK_BYTE:
                    return True, rsp, rsplen
                if b == STX_BYTE:
                    step = 1
            elif step == 1:
                rsplen_bytes += b
                if len(rsplen_bytes) == 2:
                    rsplen_bcd = int.from_bytes(rsplen_bytes, 'big')
                    rsplen = bcd2dec(rsplen_bcd)
                    step = 2
            elif step == 2:
                if b == ETX_BYTE and len(rsp) == rsplen + 4:
                    step = 3
                    continue
            elif step == 3:
                self.ack()
                return True, rsp, rsplen

        return False, rsp, rsplen

    def write(self, msg, msglen):
        buffer = dec2bcd(msglen).to_bytes(2, 'big') + \
            msg + \
            ETX_BYTE

        lrc = calc_lrc(buffer).to_bytes(1, 'big')
        full = STX_BYTE + buffer + lrc
        log.debug(f'write:{full.hex()}')

        with self._lock:
            written = self.ser.write(full)
        return written

    def form_command(self, txn_code, fields=None):
        transpt_hdr = b'60' + b'0000' + b'0000'
        present_hdr = \
            b'1' + \
            b'0' + \
            bytes(txn_code, encoding='utf8') + \
            b'00' + \
            b'0' + \
            b'\x1c'

        msg = transpt_hdr + present_hdr
        if fields != None:
            msg += enc_fields(fields)
        return msg

class EMVThread(threading.Thread):
    def __init__(self, reader=None, 
            on_acked=None,
            on_detected=None, 
            on_tapped=None, 
            on_heartbeat=None,
            *args, **kwargs):
        super(EMVThread, self).__init__(*args, **kwargs)
        self.reader = reader
        self.on_acked = on_acked
        self.on_detected = on_detected
        self.on_tapped = on_tapped
        self.on_heartbeat = on_heartbeat
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
 
    def stopped(self):
        return self._stop.isSet()
 
    def run(self):

        while True:

            if self.stopped():
                return

            rv, rsp, rsplen = self.reader.read()
            if rv == True:

                log.debug(f'read:{rsp.hex()}')

                if rsp[0:1] == ACK_BYTE:
                    if self.on_acked != None:
                        self.on_acked()
                    continue

                txn_code, rsp_code = parse_present_hdr(rsp[13:21])
                fields = dec_fields(rsp[21:len(rsp)-2])

                txn_code_str = txn_code.decode('utf8')
                rsp_code_str = rsp_code.decode('utf8')
                log.debug(f'txn_code:{txn_code_str}, rsp_code:{rsp_code_str}')

                if txn_code_str == TRANSIT_TAP_TXN_CODE:
                    if self.on_tapped != None:
                        self.on_tapped(fields)
                #elif txn_code_str == CANCEL_TXN_CODE:
                elif txn_code_str == HEARTBEAT_TXN_CODE:
                    if self.on_heartbeat != None:
                        self.on_heartbeat(fields)
                #elif txn_code_str == TMS_DOWNLOAD_TXN_CODE:
                elif txn_code_str == CARD_DETECTED_TXN_CODE:
                    if self.on_detected() != None:
                        self.on_detected()
                #elif txn_code_str == READER_REBOOT_TXN_CODE:


