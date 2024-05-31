
def form_tlv(data):
    buffer = []
    for k, v in data.items():
        buffer.append(k)
        buffer.append(len(v))
        buffer += v
    return buffer

def extract_tlv(buffer):
    data = dict()
    step = 0
    offset = 0
    buflen = len(buffer)
    while offset < buflen:
        if step == 0:
            t = buffer[offset]
            step = 1
            offset += 1
        elif step == 1:
            l = buffer[offset]
            step = 2
            offset += 1
        elif step == 2:
            v = buffer[offset:offset+l]
            step = 0
            offset += l
            data[t] = v
    return data
