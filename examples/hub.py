#!/usr/bin/python3

from cougarnet.sim.host import BaseHost
from cougarnet.util import mac_binary_to_str

class Hub(BaseHost):
    def _handle_frame(self, frame: bytes, intf: str) -> None:
        print(f'Frame received on {intf} ' + \
                f'(src: {mac_binary_to_str(frame[6:12])} ' \
                f'; dst: {mac_binary_to_str(frame[:6])})')
        for myint in self.physical_interfaces():
            if intf != myint:
                self.send_frame(frame, myint)

def main():
    Hub().run()

if __name__ == '__main__':
    main()
