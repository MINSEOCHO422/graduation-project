import json
import pandas as pd

INPUT_PATH  = r'C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\eve.json'
OUTPUT_PATH = r'C:\Users\min07\Desktop\민서 파일\홍익대학교\4학년\졸업프로젝트(1)\활용자료\Suricata 실시간 트래픽 로그\suricata_rf_features.csv'

PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPv6': 58, 'SCTP': 132}
DIR_MAP   = {'to_server': 0, 'to_client': 1}

records = []

with open(INPUT_PATH, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        et = obj.get('event_type', '')
        if et == 'stats':          # stats 이벤트는 트래픽 정보 없음 → 스킵
            continue

        flow = obj.get('flow', {})
        tcp  = obj.get('tcp', {})
        alrt = obj.get('alert', {})

        bytes_ts = flow.get('bytes_toserver', 0) or 0
        bytes_tc = flow.get('bytes_toclient', 0) or 0
        pkts_ts  = flow.get('pkts_toserver', 0) or 0
        pkts_tc  = flow.get('pkts_toclient', 0) or 0

        total_bytes = bytes_ts + bytes_tc
        total_pkts  = pkts_ts  + pkts_tc
        avg_pkt_size = (total_bytes / total_pkts) if total_pkts > 0 else 0

        proto_str = obj.get('proto', '')
        row = {
            # ── KISTI 대응 컬럼 ──────────────────────────────────────
            'sourcePort'      : obj.get('src_port', None),          # ← src_port
            'destinationPort' : obj.get('dest_port', None),         # ← dest_port
            'protocol'        : PROTO_MAP.get(proto_str, -1),       # ← proto (숫자)
            'directionType'   : DIR_MAP.get(obj.get('direction', ''), -1),  # ← direction
            'packetSize'      : total_bytes,                         # ← bytes 합산
            'eventCount'      : total_pkts,                          # ← pkts 합산
            'jumboPayloadFlag': int(avg_pkt_size > 1500),            # ← 파생
            'analyResult'     : alrt.get('severity', 0),            # ← alert.severity

            # ── Suricata 전용 추가 특징 ──────────────────────────────
            'flow_bytes_toserver': bytes_ts,
            'flow_bytes_toclient': bytes_tc,
            'flow_pkts_toserver' : pkts_ts,
            'flow_pkts_toclient' : pkts_tc,
            'flow_age'           : flow.get('age', 0) or 0,
            'tcp_syn'            : int(tcp.get('syn', False)),
            'tcp_ack'            : int(tcp.get('ack', False)),
            'tcp_fin'            : int(tcp.get('fin', False)),
            'tcp_psh'            : int(tcp.get('psh', False)),
            'alert_severity'     : alrt.get('severity', 0),

            # ── 레이블 ───────────────────────────────────────────────
            'Label'              : 1 if et == 'alert' else 0,
        }
        records.append(row)

df = pd.DataFrame(records)

print(f"총 레코드: {len(df):,}")
print(f"\nLabel 분포:")
print(df['Label'].value_counts())
print(f"\n결측값 수: {df.isnull().sum().sum()}")

df.fillna(0, inplace=True)

df.to_csv(OUTPUT_PATH, index=False, encoding='utf-8-sig')
print(f"\n저장 완료: {OUTPUT_PATH}")
print(f"\n최종 컬럼: {list(df.columns)}")
