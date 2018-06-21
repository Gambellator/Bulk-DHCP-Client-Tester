import sys
import time
import logging
import random
import progressbar
import dhcpclient.dhcpclient as dhcp

from dhcpclient.utilites import RandomMac

AVC = 'AVC999904444401'
VLAN = [2001]
INTERFACE = 'em4'
SESSIONS = 1

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    rando_mac = RandomMac()
    subscriber_list = []
    try:
        logger.info("Starting DHCP clients.")
        bar = progressbar.ProgressBar()
        for i in bar(range(1, SESSIONS + 1)):
            a = dhcp.DHCPClient(INTERFACE, rando_mac.get_mac(), vlan_tags=VLAN, option82=AVC, dsl_sub_options=[12000, 450000], no_renew=True)
            subscriber_list.append(a)
            # while True:
            #     if a.threadid:
            #         continue
        logger.info("Services loaded starting clients.")
        for a in subscriber_list:
            a.start_server()
            time.sleep(0.01)
        cps = []
        while True:
            time.sleep(1)
            i = 0
            for a in subscriber_list:
                #print a.hostname, a.server_status(), a.ciaddr, a.state.state, a.threadid
                if a.server_status() == "Bound":
                    i += 1
            if i < len(subscriber_list):
                cps.append(i)
            else:
                logger.info('CPS list = %s', cps)

            logger.info('!!!!!!!!!!!! ----  We have %s sessions up', i)

    except KeyboardInterrupt:
        for a in subscriber_list:
            print a.server_status()
            a.stop_server()
        last_number = len(subscriber_list)
        print "Closing sessions: {0}".format(last_number)
        while True:
            if len(subscriber_list) == 0:
                sys.exit()
            if subscriber_list[-1].server_status() == "Stopped":
               subscriber_list.pop()

