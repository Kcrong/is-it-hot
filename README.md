# is-it-hot
warning.or.kr 사이트 목록을 이용해 해당 사이트가 유해한지 확인하는 스크립트


프로그램 원리
-------
[Aho Corasick 알고리즘](https://ko.wikipedia.org/wiki/%EC%95%84%ED%98%B8_%EC%BD%94%EB%9D%BC%EC%8B%9D_%EC%95%8C%EA%B3%A0%EB%A6%AC%EC%A6%98) 을 이용해 저장된 유해 URL에 대한 패턴 매칭을 실시한다.  
Python 에서 Windivert 을 사용하기 위해 pydivert를 사용하였으며, 위 알고리즘은 별도 모듈을 사용하지 않았다.

실행방법
----
    $ python main.py

실행결과
----
![result.png](https://raw.githubusercontent.com/Kcrong/is-it-hot/master/result.png)
