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
        log.debug("BASE::on_tapped")
        for key, field in fields.items():
            tag = key
            taglen = field[0]
            value = field[1]
            try:
                log.info(f"{tag} {taglen:4d} {value.decode()}")
            except: # tag TE
                #TODO: decode TLV?
                log.info(f"{tag} {taglen:4d} {value.hex()}")

    def on_heartbeat(self, fields):
        log.debug("BASE::on_heartbeat")
        for key, field in fields.items():
            tag = key
            taglen = field[0]
            value = field[1]
            try:
                log.info(f"{tag} {taglen:4d} {value.decode()}")
            except:
                log.info(f"{tag} {taglen:4d} {value.hex()}")

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


