import os

VOLATILITY_PATH = 'vol.py'
VOLATILITYBOT_HOME = './'
STORE_PATH = os.path.join(VOLATILITYBOT_HOME, 'Store')

EXPLOITABLE_PROCESS_NAMES = ['iexplore.exe', 'chrome.exe', 'firefox.exe']
NORMAL_PROCESS_NAMES = ['system', 'csrss.exe', 'smss.exe', 'services.exe', 'wininit.exe', 'svchost.exe', 'runtimebroker.exe', 'lsaiso.exe', 'taskhostw.exe', 'lsass.exe', 'winlogon.exe', 'explorer.exe']
