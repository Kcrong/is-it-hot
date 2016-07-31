from time import localtime, strftime

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
        self.logfile = open('log.txt', 'a')

    @staticmethod
    def find_host(payload):
        """
        :param payload: packet bytes - string
        :return: host string ( www.google.com )
        """
        payload = payload.decode('utf-8')
        try:
            head_idx = payload.index('Host: ') + len('Host: ')
            end_idx = payload.index('\r\nConnection', head_idx)
        except ValueError:
            return False
        else:
            return payload[head_idx:end_idx]

    def filter_host(self, host):
        """
        Using Aho-Corasick, check is it bad url
        :param host: host string ( www.google.com )
        :return: boolean
        """
        # Do Aho-Corasick!!!!
        return self.filter.search_pattern(host)

    def run(self):
        """
        드라이버를 열어 패킷을 가져옵니다.
        :return: None ( Demon )
        """
        print("Running...")
        print("Start to filtering")
        with Handle(self.driver, "outbound and tcp.DstPort == 80 and tcp.PayloadLength > 0", priority=1000) as handle:
            while True:
                raw, meta = handle.recv()
                captured = self.driver.parse_packet(raw)

                host = self.find_host(captured.payload)
                time = strftime("%x %X", localtime())
                if host and not self.filter_host(host):
                    self.logfile.write("[%s] %s is allowed" % (time, host))
                    handle.send(raw, meta)
                else:
                    self.logfile.write("[%s] %s is blocked" % (time, host))


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
        """
        루트 노드를 반환
        :return: class root_node
        """
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
        """
        노드의 다음 노드 설정
        :param next_node: next_node 로 설정될 노드
        :return: None
        """
        self._next_node[next_node.char] = next_node
        next_node.set_before_node(self)

    def set_before_node(self, before_node):
        """
        :param before_node: before_node 로 설정할 노드
        :return: None
        """
        self._before_node = before_node
        self._depth = self._before_node.depth + 1

    def next_node(self, char=None):
        """
        노드의 다음 경로에서 인자로 받은 char 의 노드를 반환합니다.
        char를 특별히 지정하지 않았을 경우, 모든 다음 노드를 반환합니다.
        :param char: 찾을 char
        :return:  next_node or all_next_node_dictionary
        """
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
        """
        word_tree 에서 연산할 단어를 추가
        :param word: word to add
        :return: None
        """
        self.word_list.append(word)

    @staticmethod
    def _new_link(node, char, output_link=False):
        """
        :param node: 다음 경로를 설정할 노드
        :param char: 다음 경로로 설정될 노드의 char 값
        :param output_link: output_link 여부
        :return: None
        """
        node.set_next_node(AhoCorasickNode(char, output_link))

    def make_tree(self):
        """
        self 의 word_list 를 이용해 단어 tree 를 만듬.
        :return: None
        """
        for word in self.word_list:
            self.node_ptr = self.root_node
            for char in word[:-1]:
                if self.node_ptr.next_node(char) is False:  # char 가 해당 경로에 없을 경우
                    self._new_link(self.node_ptr, char)  # 새로운 다음 경로의 노드를 만듬

                self.node_ptr = self.node_ptr.next_node(char)  # 다음 노드로 포인터를 옮김

            if self.node_ptr.next_node(word[-1]) is False:  # word 의 마지막 글자 부분에서 다음 경로가 없을 경우
                self._new_link(self.node_ptr, word[-1], output_link=True)  # output_link 를 활성화한 노드를 생성
            else:
                self.node_ptr.output_link = True  # 있으면 해당 노드의 output_link 를 활성화

    def pretty_print(self, node=None):
        """
        생성된 노드를 출력합니다.
        :param node: 부모 노드. (없을 경우 root_node 부터 출력 --> 모두 출력)
        :return: None. Just recursion
        """
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
        """
        생성된 tree 를 이용해 인자로 받은 pattern 에서 substring 을 찾음
        :param pattern: 찾을 문자열
        :return: boolean
        """
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
