import sqlite3

TBL_TX = "TX"

FLD_ROWID = "ROWID"
FLD_SURROGATE_PAN='surrogated_pan'
FLD_PG_NONSENSITIVE_TAGS = "pg_nonsensitve_tags"
FLD_ENC_PG_SENSITIVE_TAGS = "enc_pg_sensitivetags"
FLD_CORRELCATION_ID = "correlation_id"
FLD_BSAM_KSN = "bsam_ksn"

FLDS_REQ = f"{FLD_ROWID}, " \
    + f"{FLD_CORRELCATION_ID}, " \
    + f"{FLD_SURROGATE_PAN}, " \
    + f"{FLD_ENC_PG_SENSITIVE_TAGS}, " \
    + f"{FLD_PG_NONSENSITIVE_TAGS}, " \
    + f"{FLD_BSAM_KSN} "

class BatchDbHelper:
    def __init__(self):
        self.con = None

    def open(self, filename):
        self.con = sqlite3.connect(filename)

    def close(self):
        self.con.close()

    def read_one(self, row_id):
        cur = self.con.cursor()
        stmt = f"SELECT {FLDS_REQ} FROM {TBL_TX} WHERE {FLD_ROWID}={row_id}"
        cur.execute(stmt)
        row = cur.fetchone()
        return row

    def read_all(self):
        cur = self.con.cursor()
        stmt = f"SELECT {FLDS_REQ} FROM {TBL_TX}"
        cur.execute(stmt)
        rows = cur.fetchall()
        return rows
