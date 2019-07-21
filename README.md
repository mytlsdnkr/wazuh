# Wazuh

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Coverity](https://scan.coverity.com/projects/10992/badge.svg)](https://scan.coverity.com/projects/wazuh-wazuh)

Wazuh는 운영 체제 및 응용 프로그램 수준에서 호스트를 모니터링하여 인프라에 대한 강력한 보안 가시성을 얻을 수 있도록 도와줍니다.
가벼운 멀티 플랫폼 에이전트를 기반으로하는 이 솔루션은 다음과 같은 기능을 제공합니다.

- **로그 관리 및 분석:** Wazuh 에이전트는 운영 체제 및 응용 프로그램 로그를 읽고, 이를 규칙 기반 분석 및 저장을 위해 중앙 관리자에게 안전하게 전달합니다.

- **파일 무결성 검사:** Wazuh는 파일 시스템의 내용을 모니터링하여 내용 변경, 사용 권한, 소유권 및 파일 특성등의 변경을 검사합니다.

- **침임 및 이상 탐지:** 에이전트는 malware, rootkits 또는 의심스러운 변경을 찾기위해서 시스템을 스캔하고, 숨겨진 파일, 은폐 된 프로세스 또는 등록되지 않은 네트워크 리스너, 시스템 콜 응답의 불일치를 발견 할 수 있습니다.

- **정책 및 준수 모니터링:** Wazuh는 구성 파일을 모니터링하여 보안 정책, 표준 또는 강화 가이드를 준수하는지 확인합니다. 에이전트는 취약성, 패치 부족 또는 안전하지 않은 것으로 알려진 응용 프로그램을 탐지하기 위해 주기적으로 검사를 수행합니다.

이러한 다양한 기능들은 OSSEC, OpenSCAP, Elastic Stack과 함께 통합 솔루션으로 제공되고, 설정과 관리를 단순화합니다.

Wazuh는 업데이트 된 로그 분석 ruleset과 모든 Wazuh 에이전트의 상태 및 구성을 모니터 할 수있는 RESTful API를 제공합니다.

Wazuh는 또한 로그 분석 경고 및 Wazuh 인프라 모니터링 및 관리를 위한 웹 애플리케이션 (Kibana 앱)을 포함합니다.

## Wazuh Open Source components and contributions

* [Wazuh](https://documentation.wazuh.com/current/index.html)는 [OSSEC HIDS](https://github.com/ossec/ossec-hids)를 기반으로 만들어졌고, 새로운 기능들을 추가하고, 버그를 수정하였습니다.

* [Wazuh App](https://documentation.wazuh.com/current/index.html#example-screenshots)은 로그 분석 및 경고, Wazuh 인프라를 모니터링하기 위한 
Kibana app에 통합할 수 있는 웹 어플리케이션 입니다.

* [Wazuh Ruleset](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)은 decorders, rules, rootchecks 그리고 SCAP 등을 관리하는 저장소 입니다. ruleset은 관리자가 공격, 침입, 소프트웨어 오용, 응용 프로그램 오류, 멀웨어, 루트킷, 시스템 이상 또는 보안 정책 위반을 탐지하는데 사용됩니다. 또한 PCI DSS v3.1 및 CIS와의 매핑을 포합합니다. 사용자는 pull request를 이용하여 이 ruleset을 우리의 [Github repository](https://github.com/wazuh/wazuh-ruleset)에 기여할 수 있습니다.

* [Wazuh RESTful API](https://documentation.wazuh.com/current/user-manual/api/index.html)는 Wazuh 설치를 모니터하고 제어하는데 사용되며 HTTP 요청을 보낼 수있는 모든 것에서 관리자와 상호 작용할 수있는 인터페이스를 제공합니다.

* [Pre-compiled installation packages](https://documentation.wazuh.com/current/installation-guide/packages-list/index.html)는 RedHat, CentOS, Fedora, Debian, Ubuntu and Windows와 같은 OS에서의 미리 컴파일된 패키지들을 제공합니다.

* [Puppet scripts](https://documentation.wazuh.com/current/deploying-with-puppet/index.html)는 자동으로 Wazuh를 배포하고 구성합니다.

* [Docker containers](https://documentation.wazuh.com/current/docker/index.html)는 Wazuh 관리자를 가상화 하고, ELK 스택과 통합이 가능합니다.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)

## Branches

* `stable` branch는 가장 최근의 안정화 된 버전에 해당합니다.
* `master` branch는 최근의 코드를 포함하고, 버그를 가질 가능성이 높습니다.

## Contribute

만약 당신이 우리의 프로젝트에 기여하고 싶다면 주저하지말고 request를 요청하세요. 또한 우리의 [mailing list](https://groups.google.com/d/forum/wazuh)에 참여하거나, 질문이 있거나 토론에 참여하기 위해 다음의 주소로 이메일을 보낼 수 있습니다.
[wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)

## Software and libraries used

* OpenSSL의 SHA1, Blowfish 라이브러리와 zlib을  수정한 버전을 사용
* OpenSSL 툴킷에 사용되는 OpenSSL 프로젝트 사용
* Eric Young(eay@cryptsoft.com)에 의해서 만들어진 암호화 소프트웨어
* Zlib 프로젝트 (Jean-loup Gailly and Mark Adler).
* cJSON 프로젝트 (Dave Gamble).
* Node.js (Ryan Dahl).
* NPM packages Body Parser, Express, HTTP-Auth and Moment.
* Guido van Rossum과 파이썬 개발팀에서 만든 Cython 인터프리터 (https://www.python.org).
* PyPi packages: [azure-storage-blob](https://github.com/Azure/azure-storage-python), [boto3](https://github.com/boto/boto3), [cryptography](https://github.com/pyca/cryptography), [docker](https://github.com/docker/docker-py), [pytz](https://pythonhosted.org/pytz/), [requests](http://python-requests.org/) and [uvloop](http://github.com/MagicStack/uvloop).

## Credits and Thank you

* Daniel Cid, who started the OSSEC project.
* [OSSEC core team members](http://ossec.github.io/about.html#ossec-team).
* [OSSEC developers and contributors](https://github.com/ossec/ossec-hids/blob/master/CONTRIBUTORS).

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)

Based on OSSEC
Copyright (C) 2015 Trend Micro Inc.

## References

* [Wazuh website](http://wazuh.com)
* [OSSEC project website](http://ossec.github.io)
