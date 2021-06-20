import angr
import claripy

def main():
    
    for i in range(16, 28):
        base_addr=0x400000
        input_len = i

        proj = angr.Project('./crapsemu', main_opts={'base_addr': base_addr})

        flag_chars = [claripy.BVS('flag_%i' % i, 8) for i in range(input_len)]
        flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')]) # Add \n for scanf() to accept the input

        st = proj.factory.full_init_state(
            args='./crapsemu',
            stdin=flag, 
            add_options=angr.options.unicorn
        )

        for byte in flag_chars:
            st.solver.add(byte >= b"\x20")
            st.solver.add(byte <= b"\x7e")

        sm = proj.factory.simulation_manager(st)
        sm.run()

        y = []
        for x in sm.deadended:
            if b'Congratulations' in x.posix.dumps(1):
                y.append(x)

        for s in y:
            flag = ''.join([chr(s.solver.eval(k)) for k in flag_chars])
            print("Flag: %s" % flag)


if __name__ == '__main__':
    main()

