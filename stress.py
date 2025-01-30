from base import BaseSimulator
from emv import EMVThread
import time
import log

class StressSimulator(BaseSimulator):
    def __init__(self, reader, timeout):
        super(StressSimulator, self).__init__(reader)
        self.timeout = timeout

    def on_tapped(self, fields):
        log.debug("Stress::on_tapped - IN")
        super().on_tapped(fields)
        self.reader.transit_tap()
        log.debug("Stress::on_tapped - OUT")

    def on_heartbeat(self, fields):
        super().on_heartbeat(fields)
        for key, field in fields.items():
            if key == "TG":
                if  field[1] == b'0':
                    log.error("Stress::on_heartbeat::transit_tap - IN")
                    self.reader.transit_tap()
                    log.error("Stress::on_heartbeat::transit_tap - OUT")
                else:
                    log.debug("Already polling")


    def run(self):

        th = EMVThread(reader=self.reader,
                on_acked=self.on_acked,
                on_detected=self.on_detected, 
                on_tapped=self.on_tapped, 
                on_heartbeat=self.on_heartbeat,
                daemon=True)
        th.start()

        log.info("Stress::First transit_tap")
        self.reader.transit_tap()

        try:
            while True:
                
                self.reader.heartbeat()
                time.sleep(self.timeout)

        except KeyboardInterrupt:
            th.stop()