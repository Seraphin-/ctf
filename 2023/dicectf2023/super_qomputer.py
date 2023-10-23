# super qomputer (rev)
# dice{clifford-the-big-quantum-dog-19e3f5}

import stimcirq
from cirq.contrib.qasm_import import circuit_from_qasm
import stim
from pwn import unbits

with open("./challenge.qasm") as f:
    s = f.read()
cirq_circuit = circuit_from_qasm(s)
stim_circuit = stimcirq.cirq_circuit_to_stim_circuit(cirq_circuit)

circuit = str(stim_circuit) + "\n"

measure = "M "
for i in range(400):
    measure += str(i) + " "
circuit = stim.Circuit(circuit + measure + "\n")
sampler = stim.Circuit.compile_sampler(circuit)
sample = sampler.sample(shots=1)[0]
print(unbits(sample, endian="little")[::-1])
