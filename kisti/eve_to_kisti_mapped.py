"""
eve.json -> KISTI 포맷 CSV 매핑

출력 컬럼 (KISTI 10컬럼 + packetSize):
  uid, sourceIP, destinationIP, sourcePort, destinationPort,
  protocol, attackType, eventCount, analyResult, duration, packetSize

제외 컬럼: payload, orgIDX, detectName, jumboPayloadFlag, directionType
"""
import json
import pandas as pd
from datetime import datetime

INPUT_PATH  = r'C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\로그_eve.json\20260428 eve.json'
OUTPUT_PATH = r'C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\Suricati-KISTI\suricata_kisti_mapped_20260428.csv'

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPv6': 58, 'SCTP': 132}

def classify_attacktype(signature):
    """Suricata alert signature → KISTI attackType"""
    if not signature:
        return 0
    sig = signature.upper()
    if any(k in sig for k in ['SCAN', 'SWEEP', 'NMAP', 'MASSCAN', 'PORT SCAN']):
        return 4
    if any(k in sig for k in ['MALWARE', 'TROJAN', 'WORM', 'BOTNET', 'VIRUS', 'RANSOMWARE']):
        return 1
    if any(k in sig for k in ['WEB_SERVER', 'WEB_CLIENT', 'SQL', 'XSS', 'LFI', 'RFI',
                               'WEBSHELL', 'PHP', 'CMS', 'WORDPRESS', 'JOOMLA']):
        return 2
    if any(k in sig for k in ['EXPLOIT', 'OVERFLOW', 'RCE', 'CVE', 'DOS', 'DDOS',
                               'SHELLCODE', 'STREAM', 'SMB', 'RDP', 'SSH']):
        return 3
    return 0

def calc_duration(flow, timestamp):
    """flow.age 우선, 없으면 flow.start~end 차이(초)"""
    age = flow.get('age')
    if age is not None:
        return int(age)
    try:
        start = flow.get('start', timestamp)
        end   = flow.get('end')
        if start and end:
            fmt = '%Y-%m-%dT%H:%M:%S.%f%z'
            return int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except Exception:
        pass
    return None

records = []

with open(INPUT_PATH, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            obj = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        et = obj.get('event_type', '')
        if et == 'stats':
            continue

        flow  = obj.get('flow',  {}) or {}
        alert = obj.get('alert', {}) or {}

        # 패킷/바이트 집계
        pkts_ts = flow.get('pkts_toserver', 0) or 0
        pkts_tc = flow.get('pkts_toclient',  0) or 0
        bytes_ts = flow.get('bytes_toserver', 0) or 0
        bytes_tc = flow.get('bytes_toclient',  0) or 0
        total_pkts  = pkts_ts + pkts_tc
        total_bytes = bytes_ts + bytes_tc

        # packetSize: 평균 패킷 크기 근사 (KISTI는 개별 패킷 크기)
        packet_size = round(total_bytes / total_pkts, 2) if total_pkts > 0 else 0

        signature = alert.get('signature') if et == 'alert' else None

        records.append({
            'uid'            : obj.get('flow_id'),
            'sourceIP'       : obj.get('src_ip'),
            'destinationIP'  : obj.get('dest_ip'),
            'sourcePort'     : obj.get('src_port'),
            'destinationPort': obj.get('dest_port'),
            'protocol'       : PROTO_MAP.get(obj.get('proto', ''), -1),
            'attackType'     : classify_attacktype(signature),
            'eventCount'     : total_pkts,
            'analyResult'    : 1 if et == 'alert' else None,
            'duration'       : calc_duration(flow, obj.get('timestamp')),
            'packetSize'     : packet_size,
        })

df = pd.DataFrame(records)
print(f"원본 레코드 수: {len(df):,}")

# ── 중복 제거 ─────────────────────────────────────────────────
# 같은 uid(flow_id)가 flow/alert/dns 등 여러 이벤트로 중복 기록됨
# 전략: uid별로 집계
#   - 식별 필드(sourceIP 등): 첫 번째 값 유지
#   - eventCount/packetSize/duration: 최대값 (flow 이벤트 값이 가장 완전함)
#   - attackType: 최대값 (0=미지정보다 공격 분류 우선)
#   - analyResult: 최대값 (1=정탐이 NaN보다 우선)

agg_dict = {
    'sourceIP'       : 'first',
    'destinationIP'  : 'first',
    'sourcePort'     : 'first',
    'destinationPort': 'first',
    'protocol'       : 'first',
    'attackType'     : 'max',
    'eventCount'     : 'max',
    'analyResult'    : 'max',
    'duration'       : 'max',
    'packetSize'     : 'max',
}

df_dedup = df.groupby('uid', sort=False).agg(agg_dict).reset_index()
print(f"중복 제거 후 레코드 수: {len(df_dedup):,}  (제거: {len(df) - len(df_dedup):,}건)")

print(f"\nattackType 분포:")
print(df_dedup['attackType'].value_counts().sort_index())
print(f"\nduration 통계:")
print(df_dedup['duration'].describe())
print(f"\npacketSize 통계:")
print(df_dedup['packetSize'].describe())
print(f"\n결측값:")
missing = df_dedup.isnull().sum()
print(missing[missing > 0] if missing[missing > 0].any() else "  없음")
print(f"\n최종 컬럼: {list(df_dedup.columns)}")

df_dedup.to_csv(OUTPUT_PATH, index=False, encoding='utf-8-sig')
print(f"\n저장 완료: {OUTPUT_PATH}")
