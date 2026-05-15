# ─────────────────────────────────────────────
#  졸업프로젝트 — Suricata + Random Forest IDS
#  Base: Ubuntu 22.04
# ─────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ── 시스템 패키지 ──────────────────────────────
RUN apt-get update && apt-get install -y \
    software-properties-common \
    python3 python3-pip \
    suricata \
    && rm -rf /var/lib/apt/lists/*

# Suricata 기본 룰 업데이트
RUN suricata-update || true

# ── Python 패키지 ──────────────────────────────
WORKDIR /app

COPY docker/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── 모델 & 스크립트 복사 ────────────────────────
COPY ml_model/model_rf.pkl          /app/model_rf.pkl
COPY ml_model/label_encoder.pkl     /app/label_encoder.pkl
COPY ml_model/predict_eve_docker.py /app/predict_eve_docker.py

# ── Suricata 설정: eve.json 출력 활성화 ──────────
# flow 이벤트가 기록되도록 suricata.yaml 수정
RUN sed -i 's/- eve-log:/- eve-log:\n      enabled: yes/' \
        /etc/suricata/suricata.yaml 2>/dev/null || true

# ── 실행 스크립트 ──────────────────────────────
# Suricata를 백그라운드로 띄운 뒤 Python 감시 스크립트 실행
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 로그 디렉토리
RUN mkdir -p /var/log/suricata

ENTRYPOINT ["/app/entrypoint.sh"]
