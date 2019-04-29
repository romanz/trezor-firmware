import numpy as np
from collections import deque, defaultdict

def window(iterable, n):
    buf = deque([], maxlen=n)
    for i in iterable:
        buf.append(i)
        if len(buf) == n:
            yield tuple(buf)

def split_lines(fname, types):
    for line in open(fname):
        values = line.strip().split()
        assert len(values) == len(types)
        yield tuple(T(v) for T, v in zip(types, values) if T is not None)

def main():
    from_hex = lambda v: int(v, 16)
    symbols = dict(split_lines('symbols.txt', [from_hex, None, str]))

    calls = split_lines('call-graph.txt', [None, from_hex, None, from_hex])
    usage = defaultdict(list)
    for prev, curr in window(calls, 2):
        delta = prev[1] - curr[1]
        if delta <= 0:
            continue
        symbol = symbols.get(curr[0])
        if symbol is not None:
            usage[symbol].append(delta)

    max_usage = [(max(usages), sym) for sym, usages in usage.items()]
    max_usage.sort(reverse=True)
    for i, (usage, sym) in enumerate(max_usage):
        print(f'{i:-4}) {sym:100} = {usage} bytes')


# addrs = (line.strip().rsplit(maxsplit=1)[-1] for line in lines)
# addrs = np.array([int(a, 16) for a in addrs])

# addrs = np.max(addrs) - addrs
# plt.plot(addrs)
# plt.show()

if __name__ == '__main__':
    main()
