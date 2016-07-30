from pydivert.windivert import *

with open('mal_site_edited.txt', 'r') as f:
    bad_urls = [url.split('\n')[0] for url in f.readlines()]

PROJECT_ROOT = os.path.dirname(os.path.abspath(sys.executable))
WINDIVERT_DLL_PATH = os.path.join(PROJECT_ROOT, 'DLLs', "WinDivert.dll")
WinDivert(WINDIVERT_DLL_PATH).register()


class Filter:
    def __init__(self, filter_obj):
        self.driver = WinDivert(WINDIVERT_DLL_PATH)  # WinDivertOpen
        self.filter = filter_obj

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
        # Do Aho-Corasick!!!!
        return self.filter.search_pattern(host)

    def run(self):
        print("Running...")
        print("Start to filtering")
        with Handle(self.driver, "outbound and tcp.DstPort == 80", priority=1000) as handle:
            while True:
                raw, meta = handle.recv()
                captured = self.driver.parse_packet(raw)

                # if payload?
                if len(captured.payload) != 0:
                    host = self.find_host(captured.payload)

                    if host and not self.filter_host(host):
                        print("Hello~ %s" % host)
                        handle.send(raw, meta)
                    else:
                        print("Bye~ %s" % host)

                # Not Payload, Just go....
                else:
                    handle.send(raw, meta)


class AhoCorasickNode:
    _root_node = None

    def __init__(self, char=None, output_link=False):
        self._depth = 0
        self._next_node = dict()
        self._before_node = None
        self.char = char
        self.output_link = output_link

        if char is None:
            self._set_root_node(self)

    @classmethod
    def root_node(cls):
        return cls._root_node

    @classmethod
    def _set_root_node(cls, node):
        """
        :param node: Root로 설정할 노드
        :return: None
        """
        node._depth = 0
        cls._root_node = node
        node._next_node = node

    def __repr__(self):
        return "<AhoCorasickNode %s>" % self.char

    def set_next_node(self, next_node):
        self._next_node[next_node.char] = next_node
        next_node.set_before_node(self)

    def set_before_node(self, before_node):
        self._before_node = before_node
        self._depth = self._before_node.depth + 1

    @classmethod
    def failure(cls):
        return cls.root_node

    def next_node(self, char=None):
        if char is None:
            return self._next_node
        try:
            return self._next_node[char]
        except KeyError:
            return False

    # Property 는 단지 직접 접근을 막기 위함.
    @property
    def before_node(self):
        return self._before_node

    @property
    def depth(self):
        return self._depth


class AhoCorasick:
    def __init__(self):
        self.word_list = list()
        self.root_node = self.node_ptr = AhoCorasickNode('root')

    def add_pattern(self, word):
        self.word_list.append(word)

    @staticmethod
    def _new_link(node, char, output_link=False):
        node.set_next_node(AhoCorasickNode(char, output_link))

    def make_tree(self):
        for word in self.word_list:
            self.node_ptr = self.root_node
            for char in word[:-1]:
                if self.node_ptr.next_node(char) is False:  # char가 해당 경로에 없을 경우
                    self._new_link(self.node_ptr, char)

                self.node_ptr = self.node_ptr.next_node(char)

            if self.node_ptr.next_node(word[-1]) is False:
                self._new_link(self.node_ptr, word[-1], output_link=True)
            else:
                self.node_ptr.output_link = True

    def pretty_print(self, node=None):
        if node is None:
            node = self.root_node

        print_string = "\t" * node.depth + str(node)

        if node.output_link is True:
            print_string += " - Outlink"

        print(print_string)

        next_node_dict = node.next_node()

        if len(next_node_dict) == 0:
            return None
        else:  # have next node
            for key in next_node_dict.keys():
                self.pretty_print(next_node_dict[key])

    def search_pattern(self, pattern):
        node_ptr = self.root_node

        for char in pattern:
            node_ptr = node_ptr.next_node(char)
            if node_ptr is False:
                node_ptr = self.root_node

            elif node_ptr.output_link is True:
                return True

        return False


if __name__ == '__main__':
    a = AhoCorasick()

    # 나쁜 URL 들 트리에 추가
    for bad_url in bad_urls:
        a.add_pattern(bad_url)

    # 트리 연산 필수 !!!
    a.make_tree()

    # 만들어진 트리 확인
    a.pretty_print()

    # URL 검사
    # url = "asdfmarumaru.inasd"  # url 에 좋지 못한 URL로 정의된 substring이 있으면 (marumaru.in)
    # print(url + " --> " + str(a.search_pattern(url)))  # False

    f = Filter(a)
    f.run()
