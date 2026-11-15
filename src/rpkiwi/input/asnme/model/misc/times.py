from datetime import datetime
from ..der.tags import UTC_TIME_TAG, GENERALIZED_TIME_TAG
from ..der.length import encode_tlv

def encode_utc_time(dt: datetime) -> bytes:
    utc_str = dt.strftime("%y%m%d%H%M%SZ").encode('ascii')
    return encode_tlv(UTC_TIME_TAG.encode(), utc_str)

def encode_generalized_time(dt: datetime) -> bytes:
    gen_str = dt.strftime("%Y%m%d%H%M%SZ").encode('ascii')
    return encode_tlv(GENERALIZED_TIME_TAG.encode(), gen_str)
