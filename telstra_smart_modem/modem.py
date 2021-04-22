# Library for retrieving information from a Telstra Smart Modem.
# Based on scraping the web interface which takes a very long time to respond.
# It is the only way of retrieving information from the modem without hacking it.

import telstra_smart_modem.devices as tsm_devices
from telstra_smart_modem.base import *
import time


class Modem(ModemBase):

    # Return a Devices object of all devices seen by the modem.
    def getDevices(self):

        def getDeviceModal():
            devices_response = self.session.get(
                f"{self.base_url}/modals/device-modal.lp",
                timeout=HTTP_TIMEOUT
            )
            soup = bs4.BeautifulSoup(devices_response.text, 'html.parser')
            html_table = soup.find('table', attrs={
                "id": "devices",
                "class": "table table-striped"
            })
            if html_table:
                return True, html_table
            else:
                return False, soup

        if not self.LH1000Post['httoken']:
            data = self._tryGet(getDeviceModal, "Failed to get clients from the modem")
            return tsm_devices.Devices(data)
        else:
            response = self.session.post(f"{self.base_url}/login.cgi", headers=self.LH1000Header, data=self.LH1000Post, allow_redirects=False)
            if not response.cookies:
                if response.headers['Location'] == '/login.htm?err=4':
                    raise tsm_errors.TSMBase("Too many logins")
                else:
                    raise tsm_errors.TSMBase("Errors relating to authentication")

            #LH1000 bug - loop until station list variable is complete
            loop=30
            for i in range(loop):
                response = self.session.get(f"{self.base_url}/cgi/cgi_toplogy_info.js?_tn=" + self.LH1000Post['httoken'], headers=self.LH1000Header)
                stations_info = [line.strip() for line in response.text.split(';') if line.find('stations') >= 0][1]
                if stations_info[-1] == '}':
                    break
                time.sleep(2)
            if stations_info[-1] != '}':
                raise tsm_errors.TSMBase("Error: station_info variable incomplete due to LH1000 software bug. Tried " + str(loop) + " times")
            response = self.session.post(f"{self.base_url}/logout.cgi", headers=self.LH1000Header, data=self.LH1000Post, allow_redirects=False)
            return tsm_devices.Devices(stations_info, True)

    # Return the status of the modem. (online, backup or offline)
    def getModemStatus(self):

        def getStatusModal():
            response = self.session.get(self.base_url, timeout=HTTP_TIMEOUT)
            soup = bs4.BeautifulSoup(response.text, 'html.parser')
            status = soup.find('img', attrs={"src": "img/status.png"})
            if status:
                self._extractCSRFtoken(soup)
                return True, status
            else:
                return False, soup

        def parseStatus(classname):
            switch = {
                "ok": "online",
                "backup": "backup",
                "error": "offline",
                "green": "online",
                "off": "offline"
            }
            return switch.get(classname, "unknown")

        if not self.LH1000Post['httoken']:
            img = self._tryGet(getStatusModal, "Failed to get modem status")
            return parseStatus(img['class'][0])
        else:
            response = self.session.get(f"{self.base_url}/cgi/cgi_get_led_rear.js?_tn=" + self.LH1000Post['httoken'], headers=self.LH1000Header)
            if response.status_code == 200:
                leds = {key:val for key,val in re.findall(r'^(?P<led>.*)_led = "(?P<led_state>.*?)"', response.text, re.MULTILINE)}
                leds.update({key.lower():val.lower() for key,val in re.findall(r'"function": "(?P<function>.*?)", "color": "(?P<func_state>.*?)"', response.text, re.MULTILINE)})
                return parseStatus(leds['online'])