# 제3자 라이선스 고지 (Third-Party Notices)

SecureFile은 다음 오픈소스 구성요소를 사용합니다. 각 구성요소는 해당 라이선스의
조건에 따라 사용·배포됩니다. 모든 라이선스의 저작권 고지는 원저작자에게 있습니다.

| 구성요소 | 용도 | 라이선스 |
| --- | --- | --- |
| [Python](https://www.python.org/) | 런타임 | PSF License |
| [cryptography](https://github.com/pyca/cryptography) | AES-256-GCM, PBKDF2 | Apache-2.0 / BSD-3-Clause |
| [zstandard (python-zstandard)](https://github.com/indygreg/python-zstandard) | zstd 압축 | BSD-3-Clause |
| [libzstd](https://github.com/facebook/zstd) | zstd 코어 | BSD-3-Clause |
| [Brotli (Python)](https://github.com/google/brotli) | brotli 압축 | MIT |
| [pywebview](https://github.com/r0x0r/pywebview) | 데스크탑 창(UI) | BSD-3-Clause |
| [Pillow](https://github.com/python-pillow/Pillow) | 아이콘 생성(빌드 시) | MIT-CMU (HPND) |
| [PyInstaller](https://github.com/pyinstaller/pyinstaller) | 실행파일 패키징 | GPL-2.0 (with bootloader exception) |
| [hash-wasm](https://github.com/Daninet/hash-wasm) | 웹앱 Argon2id (CDN) | MIT |

## 참고
- **PyInstaller**: 부트로더 예외 조항(bootloader exception)에 따라, PyInstaller로 패키징한
  실행파일에는 어떤 라이선스든 적용할 수 있습니다. 즉 본 소프트웨어를 MIT로 배포하는 데
  문제가 없습니다.
- **표준 라이브러리 모듈**(zlib, bz2, lzma, tkinter 등)은 Python 표준 라이브러리의 일부로
  PSF License를 따릅니다.

각 라이선스 전문은 위 링크의 원 저장소에서 확인할 수 있습니다.
