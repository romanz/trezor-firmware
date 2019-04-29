import sys
import numpy as np
import matplotlib.pyplot as plt

calls, = sys.argv[1:]
lines = iter(open(calls))
prefixes = {'E', 'X'}
addrs = (line.strip().rsplit(maxsplit=1)[-1] for line in lines if line[0] in prefixes)
addrs = np.array([int(a, 16) for a in addrs])

addrs = np.max(addrs) - addrs
plt.plot(addrs)
plt.show()
