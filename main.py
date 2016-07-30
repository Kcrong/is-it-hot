from pydivert.windivert import *

with open('mal_site_edited.txt', 'r') as f:
    bad_urls = [url.split('\n')[0] for url in f.readlines()]


def find_host(payload):
    payload = payload.decode('utf-8')
    try:
        head_idx = payload.index('Host: ') + len('Host: ')
        end_idx = payload.index('\r\nConnection', head_idx)
    except ValueError:
        return False
    else:
        return payload[head_idx:end_idx]


PROJECT_ROOT = os.path.dirname(os.path.abspath(sys.executable))
WINDIVERT_DLL_PATH = os.path.join(PROJECT_ROOT, 'DLLs', "WinDivert.dll")

# Init
WinDivert(WINDIVERT_DLL_PATH).register()

# Get Driver
driver = WinDivert(WINDIVERT_DLL_PATH)  # WinDivertOpen

# priority 는 기본적으로 1000을 많이 준다고 함.
with Handle(driver, filter="outbound and tcp.DstPort == 80", priority=1000) as handle:
    while True:
        raw, meta = handle.recv()
        captured_packet = driver.parse_packet(raw)

        # If here is HTTP payload
        if len(captured_packet.payload) != 0:
            host = find_host(captured_packet.payload)
            if host and host not in bad_urls:
                print("Hello~ %s" % host)
                handle.send(raw, meta)
            else:
                print("Bye~ %s" % host)

        handle.send(raw, meta)
