import sys
import configparser
import log
import batch
import uuid
from datetime import datetime
from cybs import CybsClient
from batch import BatchDbHelper

client = CybsClient()
helper = BatchDbHelper()

def on_invalid_arg():
    print("invalid arguments")
    sys.exit()

def print_usage():
    pass

def get_tap(args):
    if len(args) < 3:
        on_invalid_arg()
        return
    corr_id = args[2]
    client.get_tap(corr_id)

def print_record(count, row, details=True):
    row_id = row[0]
    corr_id = row[1]
    span = row[2]
    sensitive_tags = row[3]
    non_sensitve_tags = row[4]
    bsam_ksn = row[5]
    log.info(f"record[{count}]: {batch.FLD_ROWID}({row_id})")
    if details:

        log.debug(f"{batch.FLD_ROWID:20s}: {row_id}")
        log.debug(f"{batch.FLD_CORRELCATION_ID:20s}: {corr_id}")
        log.debug(f"{batch.FLD_SURROGATE_PAN:20s}: {span}")
        log.debug(f"{batch.FLD_ENC_PG_SENSITIVE_TAGS:20s}: {sensitive_tags}")
        log.debug(f"{batch.FLD_PG_NONSENSITIVE_TAGS:20s}: {non_sensitve_tags}")
        log.debug(f"{batch.FLD_BSAM_KSN:20s}: {bsam_ksn}")
        if span == "EMPTY" or corr_id == "EMPTY" or \
            sensitive_tags == "EMPTY" or \
            non_sensitve_tags == "EMPTY":
            log.error("invalid data found")

def read_all(args):
    if len(args) < 3:
        on_invalid_arg()
        return
    filename = args[2]
    helper.open(filename)
    rows = helper.read_all()
    count = 0
    for row in rows:
        print_record(count, row)
        count += 1

    helper.close()

def read_one(args):
    if len(args) < 4:
        on_invalid_arg()
        return
    filename = args[2]
    helper.open(filename)
    try:
        row = helper.read_one(args[3])
        if row != None:
            print_record(0, row)
    except:
        print("invalid row")

def send_txn(row):
    corr_id = row[1]
    span = row[2]
    sensitive_tags = row[3]
    non_sensitve_tags = row[4]
    bsam_ksn = row[5]

    if sensitive_tags == "EMPTY":
        log.error("invalid tags")
        return

    len1 = len(bsam_ksn) / 2
    len2 = len(sensitive_tags) / 2
    fluid_data = "DFEE12" + f"{int(len1):02X}" + bsam_ksn + \
        "57" + f"{int(len2):02X}" + sensitive_tags + \
        non_sensitve_tags
    print(fluid_data)
    client.send_tap(span, corr_id, fluid_data)


def process_all(args):
    if len(args) < 3:
        on_invalid_arg()
        return
    filename = args[2]
    helper.open(filename)
    rows = helper.read_all()
    for row in rows:
        send_txn(row)
    helper.close()

def process_one(args):
    if len(args) < 4:
        on_invalid_arg()
        return
    filename = args[2]
    helper.open(filename)
    try:
        row = helper.read_one(args[3])
        if row != None:
            send_txn(row)
    except:
        print("invalid row")

def verify_all(args):
    if len(args) < 3:
        on_invalid_arg()
        return
    filename = args[2]
    helper.open(filename)
    rows = helper.read_all()
    for row in rows:
        corr_id = row[1]
        if corr_id == "EMTPY":
            log.error("invalid correlation ID")
        else:
            client.get_tap(corr_id)
    helper.close()

def verify_one(args):
    if len(args) < 4:
        on_invalid_arg()
        return
    filename = args[2]
    helper.open(filename)
    try:
        row = helper.read_one(args[3])
        if row != None:
            corr_id = row[1]
            if corr_id == "EMTPY":
                log.error("invalid correlation ID")
            else:
                client.get_tap(corr_id)
    except:
        print('invalid row')
    helper.close()

# test card: 4761739000000913
def test_bsam():
    corr_id = uuid.uuid4()
    span = "a645e6c3bab95bae0cd42f8b42c931580d0a39c2f78b1eb8c59f93fb6666ce32"
    #sensitive_tags = "FCEA3B0489BCD4410729D499E48809A6" # encrpted by BSAM 101, enc counter 1
    sensitive_tags =  "246477051D6CC57A541FB29DBBA3C76B" # encrpted by BSAM 101, enc counter 2
    non_sensitve_tags= \
            "82022000" + \
            "8407A0000000031010" + \
            "95050000000000" + \
            "9A03230721" +\
            "9C0100" +\
            "5F2A020764" +\
            "5F340100" +\
            "9F0206000000000000" + \
            "9F0306000000000000" + \
            "9F100706401203A02000" +\
            "9F1A020764" +\
            "9F2608EE0EC64FAA90FF18" +\
            "9F270180" +\
            "9F33030008C8" +\
            "9F3400" + \
            "9F360204A5" + \
            "9F37040BCA90A7" + \
            "9F6E0420700000"
    

    # DFEE120A6299500010000640000A
    # 5710213BC786AA6724920CA2A6441FFD5E7C82022000
    # 8407A0000000031010
    # 95050000000000
    # 9A03230721
    # 9C0100
    # 5F2A020764
    # 5F340100
    # 9F0206000000000000
    # 9F0306000000000000
    # 9F100706401203A02000
    # 9F1A020764
    # 9F2608EE0EC64FAA90FF18
    # 9F270180
    # 9F33030008C8
    # 9F3400
    # 9F360204A6
    # 9F37047239C27D
    # 9F6E0420700000"
    #bsam_ksn = "88888851400019A00001" # from BSAM 101
    bsam_ksn = "88888851400019A00002" # from BSAM 101
    row = [
        0,
        str(corr_id),
        span,
        sensitive_tags,
        non_sensitve_tags,
        bsam_ksn
    ]
    print(row)
    send_txn(row)

if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('config.ini')

    now = datetime.now()
    filename = 'PGC' + now.strftime('%y%m%d') + '.log'
    loglevel = config.get('Logging', 'logLevel', fallback='debug')
    log.init(filename, loglevel)

    if len(sys.argv) < 2:
        print("invalid arguments")

    func = sys.argv[1]
    if func == "get_tap":
        get_tap(sys.argv)
    elif func == "read_all":
        read_all(sys.argv)
    elif func == "read_one":
        read_one(sys.argv)
    elif func == "process_all":
        process_all(sys.argv)
    elif func == "process_one":
        process_one(sys.argv)
    elif func == "verify_all":
        verify_all(sys.argv)
    elif func == "verify_one":
        verify_one(sys.argv)
    elif func == "test_bsam":
        test_bsam()

