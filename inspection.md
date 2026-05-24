 ---
  Suricata 말고 다른 도구:

  Zeek (구 Bro)
  → Suricata처럼 네트워크 트래픽 분석
  → 로그 형식이 더 풍부하고 ML 친화적
  → 실제 보안 연구에서 많이 사용
  → Suricata보다 피처 추출이 유연함

  snort
  → Suricata의 전신
  → 규칙 기반 탐지는 비슷하지만
  → 현재는 Suricata가 더 많이 쓰임

  Zeek은 실제로 ML 기반 IDS 연구에서 Suricata보다 자주 쓰입니다.
  
  ---
  2학기 방향 추천:

  방향 1: Suricata 2차 탐지 IDS 고도화
  → Suricata alert를 ML 피처로 직접 연결
  → 현재 파이프라인 개선
  → 연속성 있음 (1학기 결과 활용)

  방향 2: Zeek으로 교체
  → ML 친화적 로그 생성
  → 피처 분포 불일치 문제 개선 가능성
  → 새로운 도구 학습 필요

  방향 3: 다양한 가상환경 실험
  → GNS3, EVE-NG 등 네트워크 시뮬레이터
  → 더 현실적인 네트워크 환경 구성 가능
  → 하지만 구축 난이도가 높음
  
  ---
  솔직한 의견:

  1학기에 이미
  → 파이프라인 완성
  → 실패 원인 분석 완료
  → 부분 탐지 성공

  2학기는 방향 1이 현실적
  → Suricata alert를 ML 피처로 추가
  → SSH 외 다른 공격도 탐지 시도
  → 1학기 한계를 2학기에 개선하는 흐름

  Suricata가 한계가 아니라, Suricata와 ML을 제대로 연결하는 설계가 부족했던 것이 1학기의 핵심 발견입니다. 그걸
  2학기에 개선하면 자연스러운 1년짜리 프로젝트 흐름이 됩니다.

  ---
  ❯ Zeek이 ML에 더 친화적인 이유?                                                                           

⏺ Suricata 로그 (eve.json) 구조:

  {
    "src_ip": "172.20.0.20",
    "dest_port": 22,
    "proto": "TCP",
    "flow": {
      "pkts_toserver": 15,
      "bytes_toserver": 1690
    }
  }

  기본적으로 연결 단위 요약 정보만 제공합니다.
  
  ---
  Zeek 로그 구조:

  conn.log     → 연결 정보
  http.log     → HTTP 요청 상세
  dns.log      → DNS 쿼리
  ssl.log      → SSL/TLS 정보
  files.log    → 전송 파일 정보
  weird.log    → 프로토콜 이상

  프로토콜별로 자동 분리된 로그가 생성됩니다.
  
  ---
  ML 친화적인 이유:

  Suricata
  → 피처 추출을 직접 해야 함
  → convert.py 같은 변환 스크립트 필요
  → 피처가 제한적 (6개)

  Zeek
  → 프로토콜별 상세 피처 자동 추출
  → HTTP URI, User-Agent, 응답코드 등
  → 수십 개 피처가 바로 CSV처럼 저장
  → ML 모델에 바로 입력 가능

  ---
  예시로 비교:

  HTTP 공격 트래픽 분석 시
  
  Suricata
  → packetSize, eventCount 등 숫자만
  → XSS인지 LFI인지 구분 불가

  Zeek http.log
  → uri: "/?q=<script>alert()</script>"
  → method: POST
  → status_code: 404
  → user_agent: sqlmap/1.0
  → 공격 유형 구분 가능
  
  ---
  결론:
  
  Suricata = 규칙 기반 탐지에 최적화
             ML 피처는 부족
  
  Zeek     = 처음부터 분석/연구 목적 설계
             ML에 필요한 풍부한 피처 자동 생성

  2학기에 Zeek을 도입하면 HTTP 공격 같은 단건 요청도 URI 내용 기반으로 피처화할 수 있어서 ML 탐지 가능성이
  높아집니다.

