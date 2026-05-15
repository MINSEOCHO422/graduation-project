#!/bin/bash
set -e

# 네트워크 인터페이스 (환경변수로 오버라이드 가능, 기본 eth0)
IFACE="${SURICATA_IFACE:-eth0}"

echo "[*] Suricata 시작 (인터페이스: $IFACE)"
suricata -i "$IFACE" --pidfile /var/run/suricata.pid -D \
    --set outputs.1.eve-log.enabled=yes \
    -l /var/log/suricata/ 2>&1 | tee /var/log/suricata/suricata-start.log &

# Suricata가 eve.json 생성하기까지 잠시 대기
sleep 3

echo "[*] Random Forest 추론 스크립트 시작"
exec python3 /app/predict_eve_docker.py
