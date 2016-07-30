from pydivert.windivert import *

with open('mal_site_edited.txt', 'r') as f:
    bad_urls = [url.split('\n')[0] for url in f.readlines()]

PROJECT_ROOT = os.path.dirname(os.path.abspath(sys.executable))
WINDIVERT_DLL_PATH = os.path.join(PROJECT_ROOT, 'DLLs', "WinDivert.dll")


class Filter:
    def __init__(self):
        self.driver = WinDivert(WINDIVERT_DLL_PATH)  # WinDivertOpen
        self.handle = self.get_handle("outbound and tcp.DstPort == 80")

    def get_handle(self, filter_text):
        return Handle(self.driver, filter_text, priority=1000)

    @staticmethod
    def find_host(payload):
        payload = payload.decode('utf-8')
        try:
            head_idx = payload.index('Host: ') + len('Host: ')
            end_idx = payload.index('\r\nConnection', head_idx)
        except ValueError:
            return False
        else:
            return payload[head_idx:end_idx]

    def filter_host(self, host):
        # We have to make Aho-Corasick!!!!
        return False

    def run(self):
        while True:
            raw, meta = self.handle.recv()
            captured = self.driver.parse_packet(raw)

            # if payload?
            if len(captured.payload) != 0:
                host = self.find_host(captured.payload)

                if host and self.filter_host(host):
                    print("Hello~ %s" % host)
                    self.handle.send(raw, meta)
                else:
                    print("Bye~ %s" % host)

            # Not Payload, Just go....
            else:
                self.handle.send(raw, meta)

if __name__ == '__main__':
    f = Filter()
    f.run()
