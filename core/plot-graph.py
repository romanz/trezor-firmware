import numpy as np
import matplotlib.pyplot as plt

lines = iter(open('call-graph.txt'))
addrs = (line.strip().rsplit(maxsplit=1)[-1] for line in lines)
addrs = np.array([int(a, 16) for a in addrs])

addrs = np.max(addrs) - addrs
plt.plot(addrs)
plt.show()
