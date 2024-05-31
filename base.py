from emv import EMVThread
import log

class BaseSimulator():

    def __init__(self, reader):
        self.reader = reader

    def on_acked(self):
        log.info("on_acked")    

    def on_detected(self):
        log.info("on_detected")

    def on_tapped(self, fields):
        log.info("on_tapped")
        for field in fields:
            tag = field[0]
            taglen = field[1]
            value = field[2]
            if tag == b'TE':
                log.info(f"{tag.decode()} {taglen:4d} {value}")
                #TODO: decode TLV?
            else:
                log.info(f"{tag.decode()} {taglen:4d} {value.decode()}")

    def on_heartbeat(self, fields):
        log.info("on_heartbeat")
        for field in fields:
            tag = field[0]
            taglen = field[1]
            value = field[2]
            log.info(f"{tag.decode()} {taglen:4d} {value.decode()}")

    def run(self):
        th = EMVThread(reader=self.reader,
                on_acked=self.on_acked,
                on_detected=self.on_detected, 
                on_tapped=self.on_tapped, 
                on_heartbeat=self.on_heartbeat,
                daemon=True)
        th.start()

        try:
            while True:
                command = input(">")
                if command == "exit":
                    th.stop()
                    break

                if command == "heartbeat":
                    self.reader.heartbeat()
                elif command == "heartbeat0":
                    self.reader.heartbeat(0)
                elif command == "heartbeat1":
                    self.reader.heartbeat(1)
                elif command == "tap":
                    self.reader.transit_tap()
                elif command == "cancel":
                    self.reader.cancel()
                elif command == "download":
                    self.reader.download()
                elif command == "reboot":
                    self.reader.reboot()

        except KeyboardInterrupt:
            th.stop()


