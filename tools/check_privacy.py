"""Static privacy release invariants, not a substitute for device packet capture."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
root = Path(__file__).resolve().parents[1]
manifest = ET.parse(root / 'app/src/main/AndroidManifest.xml').getroot()
ns = '{http://schemas.android.com/apk/res/android}'
ALLOWED = {'INTERNET', 'ACCESS_NETWORK_STATE', 'FOREGROUND_SERVICE', 'FOREGROUND_SERVICE_SYSTEM_EXEMPTED', 'POST_NOTIFICATIONS'}
requested = {e.get(ns + 'name').rsplit('.', 1)[1] for e in manifest.findall('uses-permission')}
assert requested == ALLOWED, f'Permission set changed: {requested ^ ALLOWED}'
app = manifest.find('application')
assert app.get(ns + 'allowBackup') == 'false'
assert app.get(ns + 'usesCleartextTraffic') == 'false'
services = app.findall('service')
assert {x.get(ns + 'name') for x in services} == {'.AegisVpnService', '.AgentGatewayService'}, 'Only the DNS VpnService and the agent gateway may be declared'
gateway = [x for x in services if x.get(ns + 'name') == '.AgentGatewayService'][0]
assert gateway.get(ns + 'permission') is None and [a.get(ns + 'name') for a in gateway.iter('action')] == ['com.aegis.app.AGENT_FIREWALL']
gw_src = (root / 'app/src/main/java/com/aegis/app/AgentGatewayService.kt').read_text()
assert 'sendingUid' in gw_src and 'status(pkg, cert)' in gw_src, 'Gateway must identify and pin every caller'
svc = [x for x in services if x.get(ns + 'name') == '.AegisVpnService'][0]
assert svc.get(ns + 'name') == '.AegisVpnService' and svc.get(ns + 'permission') == 'android.permission.BIND_VPN_SERVICE'
assert svc.get(ns + 'foregroundServiceType') == 'systemExempted'
acts = {x.get(ns + 'name'): x.get(ns + 'exported') for x in app.findall('activity')}
assert acts == {'.MainActivity': 'true', '.BrokerActivity': 'false'}, f'Activities changed: {acts}'
assert not app.findall('receiver') and not app.findall('provider'), 'No receivers/providers expected'
QUERIES = {'android.accessibilityservice.AccessibilityService', 'android.service.notification.NotificationListenerService', 'android.view.InputMethod',
           'android.app.action.DEVICE_ADMIN_ENABLED', 'android.provider.Telephony.SMS_DELIVER', 'android.net.VpnService'}
queried = {a.get(ns + 'name') for q in manifest.findall('queries') for a in q.iter('action')}
assert queried == QUERIES and not any(q.findall('package') or q.findall('provider') for q in manifest.findall('queries')), f'Package-visibility queries changed: {queried ^ QUERIES}'
svc_src = (root / 'app/src/main/java/com/aegis/app/AegisVpnService.kt').read_text()
assert 'addRoute("0.0.0.0"' not in svc_src and 'addRoute(\"::\"' not in svc_src, 'Tunnel must never route all traffic'
assert svc_src.count('.addRoute(') == 2 and 'addRoute(DNS4, 32).addRoute(DNS6, 128)' in svc_src, 'Only the two virtual DNS addresses may be routed'
assert 'addAllowedApplication' not in svc_src and 'addDisallowedApplication' not in svc_src
ui = (root / 'app/src/main/java/com/aegis/app/Texts.kt').read_text()
codes = set()
for name in ['UrlAnalyzer.java', 'ScamAnalyzer.java', 'ThreatChecks.java', 'MessageAi.java']:
    codes.update(re.findall(r'new Finding\("([A-Z_]+)"', (root/'core/src/main/java/com/aegis/core'/name).read_text()))
translated = set(re.findall(r'"([A-Z_]+)"', ui.split('internal fun norwegianFinding', 1)[1]))
assert codes <= translated, f'Missing Norwegian finding labels: {codes - translated}'
for f in (root/'app/src/main/res').rglob('*.xml'): ET.parse(f)
print(f'PASS: exact permission set, DNS-only VpnService with host-routes only, backup/cleartext off, XML, {len(codes)} Norwegian finding mappings')
