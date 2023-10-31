#!/bin/python3
import sys
import numpy as np

a = np.genfromtxt(sys.argv[1], delimiter=",")
a = a / 1000
a = a[1:]
print(a.mean())
print(np.quantile(a,0.25))
print(np.median(a))
print(np.quantile(a,0.75))
print(np.min(a))
print(np.max(a))
print(np.std(a))