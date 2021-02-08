import angr
project = angr.Project("./lost_in_your_eyes", auto_load_libs=False)

log = open("memory_trace", "w")

@project.hook(0x401420)
def dump(state):
    mem = state.memory.load(state.regs.rdi, size=8)
    log.write(repr(list([mem[n:n-7].args[0] for n in range(63, 0, -8)])))
    log.write("\n")
    log.flush()

simgr = project.factory.simulation_manager(project.factory.full_init_state(stdin="\x1b[D\x1b[D\n"))
simgr.run()
log.close()
