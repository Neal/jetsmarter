from Crypto.Cipher import AES
from datetime import datetime
from time import sleep
import pickledb
import requests
import logging
import base64
import json
import os

SLEEP_INTERVAL = float(os.getenv('JETSMARTER_INTERVAL', 300))
PUSHOVER_API_TOKEN = os.environ.get('PUSHOVER_API_TOKEN')
PUSHOVER_USER_TOKEN = os.environ.get('PUSHOVER_USER_TOKEN')
JETSMARTER_DEVICE_ID = os.environ['JETSMARTER_DEVICE_ID']

VALID_ICAO = ('K', 'M', 'T')

logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO'), format='%(asctime)-15s %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

class Pushover(object):
    def __init__(self, apiKey, userToken):
        self.apiKey = apiKey
        self.userToken = userToken

    def sendNotification(self, message, title):
        data = {
            'token': self.apiKey,
            'user': self.userToken,
            'message': message,
            'title': title,
            'url': 'jetsmarter://',
            'url_title': 'Open JetSmarter App',
        }
        requests.post('https://api.pushover.net/1/messages.json', data=data)

class JetSmarter(object):
    def __init__(self, deviceId):
        self.deviceId = deviceId

    def payload(self):
        data = {'device': self.deviceId, 'lat': 37.781467, 'lon': -122.4068698}
        r = requests.post('https://api.jetsmarter.com/legsforclient6?lang=en-US', data=data)
        r.raise_for_status()
        json = r.json()
        return json['payload']

    def emptyLegs(self):
        payload = base64.b64decode(self.payload())
        key = self.deviceId[:16]
        iv = self.deviceId[-16:]
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        decryptedPayload = self._unpad(encryptor.decrypt(payload))
        return json.loads(decryptedPayload)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

prettyDate = lambda d: datetime.strptime(d, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%a %d %b %H:%M')
routeInfo = lambda l: '{} [{} - {}]'.format(l['extended_info']['info'], l['from'], l['to'])

pushover = Pushover(PUSHOVER_API_TOKEN, PUSHOVER_USER_TOKEN)
jetsmarter = JetSmarter(JETSMARTER_DEVICE_ID)

def notifyLegInfo(leg, title):
    flightTime = '{} for {}'.format(prettyDate(leg['departLocal']), leg['flightTime'])
    seatsLeft = 'Seats left: {} of {} ({})'.format(leg['seatsLeft'], leg['seatsTotal'], leg['extended_info']['model'])
    message = '{}\n{}\n{}'.format(routeInfo(leg), flightTime, seatsLeft)

    print('==================================================')
    print('{} ({})'.format(title, leg['leg_id']))
    print(message)
    print('==================================================')

    try:
        pushover.sendNotification(message, title)
    except:
        pass

def fetchEmptyLegs():
    db = pickledb.load('emptylegs.json', False)
    cachedLegs = db.getall()

    logger.info('fetching empty legs')

    emptyLegs = jetsmarter.emptyLegs()

    logger.info('total legs: %s', len(emptyLegs['legs']))

    numCharterLegs = 0
    numIgnoredLegs = 0
    numCachedLegs = 0

    for leg in emptyLegs['legs']:
        legId = str(leg['leg_id'])

        if leg['jetDealType'] == 'CharterSeat':
            numCharterLegs += 1
            continue

        if not leg['from'].startswith(VALID_ICAO) and not leg['to'].startswith(VALID_ICAO):
            logger.debug('ignoring empty leg (%s) %s', legId, routeInfo(leg))
            numIgnoredLegs += 1
            continue

        seatsLeft = int(leg['seatsLeft'])

        if legId not in cachedLegs:
            notifyLegInfo(leg, 'New Empty Leg')
        else:
            cachedLegs.remove(legId)
            numCachedLegs += 1
            if db.get(legId) == 0 and seatsLeft > 0:
                notifyLegInfo(leg, 'Empty Leg Seat Now Available')

        db.set(legId, seatsLeft)

    for legId in cachedLegs:
        logger.debug('removing cached leg: %s', legId)
        db.rem(legId)

    db.dump()

    logger.info('%d charter legs ignored', numCharterLegs)
    logger.info('%d empty legs ignored', numIgnoredLegs)
    logger.info('%d empty legs cached', numCachedLegs)

def main():
    while True:
        try:
            fetchEmptyLegs()
        except Exception as e:
            logger.error(e)
        sleep(SLEEP_INTERVAL)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.debug('shutdown requested; exiting')
