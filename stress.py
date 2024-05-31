from base import BaseSimulator
from emv import EMVThread
import time
import log

class StressSimulator(BaseSimulator):
    def __init__(self, reader, timeout):
        super(StressSimulator, self).__init__(reader)
        self.timeout = timeout

    def on_tapped(self, fields):
        super().on_tapped(fields)
        self.reader.transit_tap()

    def on_heartbeat(self, fields):
        super().on_heartbeat(fields)
        for field in fields:
            if field[0] == b'TG' and field[2] == b'0':
                self.reader.transit_tap()


    def run(self):

        th = EMVThread(reader=self.reader,
                on_acked=self.on_acked,
                on_detected=self.on_detected, 
                on_tapped=self.on_tapped, 
                on_heartbeat=self.on_heartbeat,
                daemon=True)
        th.start()

        self.reader.transit_tap()

        try:
            while True:
                
                self.reader.heartbeat()
                time.sleep(self.timeout)

        except KeyboardInterrupt:
            th.stop()