# NETALYZR TEST SUMMARY TEXT MATERIAL
# ======================================================================

# Units
# -----
B = 'bytes'
KB = 'Kbytes'
MB = 'Mbytes'

Bps = 'Bits/sec'
Kbps = 'Kbit/sec'
Mbps = 'Mbit/sec'

# Test outcome status messages
# ----------------------------
StatusNotExec = 'Not Executed'
StatusProhibited = 'Prohibited'
StatusNotCompleted = 'Failed to Complete'
StatusOK = 'OK'
StatusWarning = 'Warning'
StatusFailed = 'Failed'
StatusDanger = 'Danger'
StatusNote = 'Note'
StatusDownload = 'Download %s'
StatusUpload = 'Upload %s'
StatusUpDown = 'Upload %s, Download %s'
StatusV6Problem = 'IPv6 Connectivity Problem'
StatusV6None = 'No IPv6 Support'

# Various in-server strings
# ----------------------------------------------------------------------

NetalyzrProblem = '''<p>
It appears there was a significant problem with Netalyzr's execution
in this run, as it was not able to look up the name of our server
and/or generate connections to our server.  As a result, the following
results should be considered unreliable.
</p>
<p>
Our first suggestion is to quit your web browser and try again.  If
that fails, please <a href="mailto:netalyzr-help@icsi.berkeley.edu">contact us</a>
and we will attempt to diagnose and debug the problem.  Thanks, and
sorry for the inconvenience.
</p>'''

NetalyzrOverload = 'Due to significant load on our servers, this test is currently disabled. '
DNSWildcardLink = "Wildcard DNS content"
TimeNextDay = 'next day'
Referrer = 'Referrer'
NoResults = 'No results available. '
MinorAberrations = 'Minor Aberrations'
MajorAbnormalities = 'Major Abnormalities'
InternalError = 'Internal Server Error on Test Report'
SummaryNoteworthy = 'Summary of Noteworthy Events'
NoServerTranscript = 'No server-side transcript available, sorry. '
NoClientTranscript = 'No client-side transcript available, sorry. '

# Generic test outcomes
# -----------------------

TestNotExecuted = \
"The test was not executed. Required functionality was unavailable or not permitted."

TestFailedToComplete = \
"The test failed to execute completely."

TestProhibited = \
"""The applet was not permitted to run this test in its entirety. We
encourage you to re-run the applet, allowing it to conduct its tests
if prompted.  However, some system configurations will always block
this test.  See the corresponding <a href="/faq.html#permissions"
target="_blank">FAQ</a> for help."""

TestError = \
"An unspecified error occurred during the test."

TestErrorUnknownHost = \
"One or more of the hostnames required for the test could not be resolved."

TestErrorIO = \
"An I/O error occurred during the test. The test result code is %i."

TestFailed = "Failed"

# Are there things of significant note

NoProblems = \
"""We did not observe any significant problems with your network connection"""

Problems = \
"""We observed the following problems which may be of significant concern: """

NoWarnings = \
"""We did not observe any minor aberrations"""

Warnings = \
"""We observed the following minor to moderate abnormalities: """


# Test category names
# -------------------
CatAddress = 'Address-based Tests'
CatReachability = 'Reachability Tests'
CatAccessLink = 'Network Access Link Properties'
CatHTTP = 'HTTP Tests'
CatDNS = 'DNS Tests'
CatIPv6 = 'IPv6 Tests'
CatFuture = 'Internet Extensibility'
CatHost = 'Host Properties'
CatFeedback = 'Feedback'

# Test names
# ----------

CheckLocalAddr = 'NAT detection'
CheckLocalInterface = 'Local Network Interfaces'
CheckURL = 'Address-based HTTP proxy detection'
CheckLowHTTP = 'Header-based HTTP proxy detection'
CheckMalformedHTTP = 'HTTP proxy detection via malformed requests'
CheckHTTPCache = 'HTTP caching behavior'
CheckRestrictedDNS = 'Restricted domain DNS lookup'
CheckBandwidth = 'Network bandwidth measurements'
CheckBuffer = 'Network buffer measurements'
CheckDNSResolver = 'DNS resolver properties'
CheckLatency = 'Network latency measurements'
CheckTCPSetupLatency = 'TCP connection setup latency'
CheckBackgroundHealth = 'Network background health measurement'
CheckUnrestrictedDNS = 'Unrestricted domain DNS lookup'
CheckDirectedEDNS = 'Direct EDNS support'
CheckDirectDNS = 'Direct DNS support'
CheckPathMTU = 'Path MTU'
CheckPathMTUV6 = 'IPv6 Path MTU'
CheckTraceroute = 'Traceroute'
CheckTracerouteV6 = 'IPv6 Traceroute'
CheckJS = 'JavaScript-based tests'
CheckDNSGlue = 'DNS glue policy'
CheckDNSLookups = 'DNS lookups of popular domains'
CheckUDPConnectivity = 'UDP connectivity'
CheckTCPConnectivity = 'TCP connectivity'
CheckFiletypeFiltering = 'Filetype-based filtering'
CheckDNSResolverAddress = 'DNS resolver address'
CheckDNSRand = 'DNS resolver port randomization'
CheckDNSProxy = 'DNS external proxy'
CheckClockAccuracy = 'System clock accuracy'
CheckUploadedData = 'Uploaded Data'
CheckBrowser = 'Browser properties'
CheckDNSWildcarding = 'DNS results wildcarding'
CheckDNSHostInfo = 'DNS-based host information'
CheckIPv6DNS = 'DNS support for IPv6'
CheckIPv6Connectivity = 'IPv6 Connectivity'
CheckIPv6TCPConnectivity = 'IPv6 TCP connectivity'
CheckIPv6Javascript = 'IPv6 and Your Web Browser'

CheckFutureHost = 'Readiness of your Host'
CheckFutureNat = 'Readiness of your Nat'
CheckFutureNetwork = 'Readiness of your Network'


# Test-specific material
# ----------------------

# LocalAddress/Nat testing text
LocalAddressRoutable = 'routable'
LocalAddressUnroutable = 'unroutable'

LocalAddressSummaryNoNat = '''No NAT Detected'''
LocalAddressSummaryNat = '''NAT Detected'''
LocalAddressSummaryNatUnknown = '''Unknown NAT Status'''

LocalAddressContentFailure = '''<P>One of the connections to our 
server did not receive the expected data.</P>'''

LocalAddressNoNat = '''<P>Your global IP address is %s and matches 
your local one.  You are not behind a NAT.</P>'''

LocalAddressUnknown = '''<p>Your global IP address is %s. Your local
IP address could not be determined, so we cannot say whether you are
behind a NAT.</p>'''

LocalAddressNatUnknown = '''<p>Your global IP address is %s. Your local
IP address could not be determined, so we cannot say whether you are
behind a NAT.</p>'''

LocalAddressNat = '''<P>Your global IP address is %(global)s while your local one
is %(local)s. You are behind a NAT. Your local address is in %(routable)s address space.</P>'''

LocalAddressNatNoRoute = '''<P>Your global IP address is %(global)s while your
local one is %(local)s. You are behind a NAT.</P>'''

LocalAddressMultiple = '''<P>Repeated requests arrived 
from %d different client addresses.</P>'''

LocalAddressNatSequential = '<P>Your NAT renumbers TCP source ports sequentially.  '
LocalAddressSequential = '<P>Your machine numbers TCP source ports sequentially.  '

LocalAddressNatRandom = '<P>Your NAT randomizes TCP source ports.  '
LocalAddressRandom = '<P>Your machine randomizes TCP source ports.  '


LocalAddressGraph = '''The following graph shows connection 
attempts on the X-axis and their corresponding source ports used by your computer on the Y-axis.</P>'''

NatRenumbered = '<P>The NAT or some other process renumbers TCP ports. '
Renumbered = '<P>Some network process renumbers TCP ports. '
NoRenumbered = '<P>TCP ports are not renumbered by the network.</P>'

RenumberedGraph = '''The following graph shows connection 
attempts on the X-axis and their corresponding source ports on the Y-axis as seen by our server.</P>'''

NoPortInfo = '''Client-side connection port numbers are unavailable so
we cannot report on their randomization.</p>'''


# Network interface

LocalInterfaceIntro = '''Your computer reports the following network
interfaces, with the following IP addresses for each one: '''

LocalInterfaceName = '''%s: %s'''

LocalInterfaceLoopback = '''(a local loopback interface)'''
LocalInterfaceEthernet = '''(an ethernet interface)'''
LocalInterfaceVmnet = '''(a virtual machine interface)'''

LocalIPv4Private = '''(a private IPv4 address)'''
LocalIPv4Loopback = '''(an IPv4 loopback address)'''
LocalIPv4Public = '''(a public IPv4 address)'''
LocalIPv4SelfAssigned = '''(a link-local IPv4 address)'''

LocalIPv6LinkLocal = '''(a link-local IPv6 address)'''
LocalIPv6Loopback = '''(an IPv6 loopback address)'''
LocalIPv6Private = '''(a private IPv6 address)'''
LocalIPv66to4 = '''(a 6to4 IPv6 address)'''
LocalIPv6Teredo = '''(a Teredo IPv6 address)'''
LocalIPv66rd = '''(probably a 6rd IPv6 address)'''
LocalIPv6Public = '''(probably a public IPv6 address)'''


LocalInterfaceIPv6Problem = '''Your system has an IPv6 address that
does not work'''

LocalInterfaceIPv6Warning = '''There may be a potential IPv6-related problem with your host or network'''

LocalInterfaceIPv6ProblemTxt = '''<P>Your system has an IPv6 address, yet
was unable to fetch an image using IPv6.  This can cause substantial
problems as your web browser or other programs may first attempt to
contact hosts using the non-functional IPv6 connection.  %s</P>'''

LocalInterfaceIPv6Problem6to4 = '''This is probably due to your use of
6to4 (an IPv6 transition technology) while you are behind a NAT or
firewall.  You should probably disable 6to4 on your host or NAT. '''


LocalInterfaceIPv6PrivateGateway = '''<P>Your system is configured to
use 6to4 (an IPv6 transition technology) but it is behind a NAT.  You
should probably disable 6to4 on your host (usually this is in the
network settings on your host).  This is likely why some web sites may
feel 'slow' or fail to load altogether.</P>'''

LocalInterfaceIPv6RogueGateway = '''<P>Elsewhere on your local network
is one or more 'rogue IPv6 gateway(s)', computers which is mistakenly
attempting to 'share' an IPv6 address with the local network.  These
systems may cause connectivity problems for everyone else on your
local network, which may make some sites feel 'slow' or even fail to
load altogether.  The IP address(es) are %s.</P>'''

LocalInterfaceIPv6RogueGatewayPossible = '''<P>Elsewhere on your local network
is one or more 'rogue IPv6 gateway(s)', computers which are attempting
ttempting to 'share' an IPv6 address with the local network.  These
systems may cause connectivity problems for everyone else on your
local network, which may make some sites feel 'slow' or even fail to
load altogether, although at this time you have IPv6 connectivity.
The IP address(es) are %s.</P>'''


# DNS lookup tests

HostAuxWarning = '''You are listed on a significant DNS blacklist'''

HostLookupFailure = '''We could not determine your global IP 
address for non-HTTP traffic and therefore could not conduct 
DNS-based blacklist lookups that would require this address. '''

HostIsNotTor = '''You are not a <a
href="http://www.torproject.org">Tor</a> exit node for HTTP traffic. '''

HostIsTor = '''You are listed as a <a
href="http://www.torproject.org">Tor</a> exit node for HTTP
traffic. '''

HostIsNotSpamhaus = '''You are not listed on any <a
href="http://www.spamhaus.org">Spamhaus</a> blacklists. '''

HostIsSpamhausOnlyPBL = '''You are listed on the 
<a href="http://www.spamhaus.org">Spamhaus</a> 
<A HREF="http://www.spamhaus.org/pbl/">Policy Based Blacklist</A>,
meaning that your provider has designated your address block as
one that should only be sending authenticated email, email through the ISP's
mail server, or using webmail. '''

HostIsSpamhaus = '''You are listed on the following 
<A HREF="http://www.spamhaus.org">Spamhaus</A> blacklists: '''

HostIsSpamhausSBL = '<a href="http://www.spamhaus.org/sbl/">SBL</a> '
HostIsSpamhausXBL = '<a href="http://www.spamhaus.org/xbl/">XBL</a> '
HostIsSpamhausPBL = '<a href="http://www.spamhaus.org/pbl/">PBL</a> '

HostIsSorbsDynamic = '''The 
<a href="http://www.au.sorbs.net/faq/dul.shtml">SORBS DUHL</a> 
believes you are using a dynamically assigned IP address. '''

HostIsSorbsStatic = '''The 
<a href="http://www.au.sorbs.net/faq/dul.shtml">SORBS DUHL</a> 
believes you are using a statically assigned IP address. '''

HostIsSpamhausWarning = '''Your host appears to be considered
a known spammer by the Spamhaus blacklist'''


UDPReachabilityWarning = 'Certain UDP protocols are blocked in outbound traffic'
TCPReachabilityWarning = 'Certain TCP protocols are blocked in outbound traffic'

ReachabilityUDPOK = 'Basic UDP access is available. '

ReachabilityUDPFailed = '''<BR>We are unable to deliver non-DNS UDP
datagrams to our servers.<BR>Possible reasons include a restrictive
Java security policy, a blocking rule imposed by your firewall
or personal firewall configuration, or filtering performed by your
ISP. Although it means we cannot conduct the latency and bandwidth
tests, it does not necessarily indicate a problem with your network. '''

ReachabilityUDPWrongData = '''UDP datagrams to arbitrary ports
succeed, but do not receive the expected content. '''

# Traceroute

tracerouteV4HopcountProblem = """<p>We could not determine the number of
network hops between our server and your system over IPv4.</p>"""

tracerouteV6HopcountProblem = """<p>We could not determine the number of
network hops between our server and your system over IPv6.</p>"""

tracerouteV4V6HopcountProblem = """We could determine the number of
network hops between our server and your system neither over IPv4 nor
IPv6."""

tracerouteHops = '''<p>It takes %s network hops for traffic to pass
from our server to your system, as shown below. For each hop, the time
it takes to traverse it is shown in parentheses.</p>'''
tracerouteHopsIP = '''%s'''
tracerouteHopsIPLatency = '''%s (%i ms)'''

tracerouteV4Hops = '''<p>It takes %s network hops for traffic to pass
from the same server to your system over IPv4, as shown below. For
each hop, the time it takes to traverse it is shown in
parentheses.</p>'''
tracerouteV4HopsIP = '''%s'''
tracerouteV4HopsIPLatency = '''%s (%i ms)'''

tracerouteV6Hops = '''<p>It takes %s network hops for IPv6 traffic to
pass from our IPv6 server to your system, as shown below. For each
hop, the time it takes to traverse it is shown in parentheses.</p>'''
tracerouteV6HopsIP = '''%s'''
tracerouteV6HopsIPLatency = '''%s (%i ms)'''

# V4 version

pathMTUSend = '''The path between your network and our system supports
an MTU of at least %i bytes,'''

# Article can be "The" or " and the", if this is used as a continuing
# sentence.
pathMTUAndThe = " and the"
pathMTUThe = 'The'
pathMTURecv = '''%(article)s path between our system and your network has an
MTU of %(mtu)i bytes. '''

pathMTUBottleneck = '  The bottleneck is at IP address %s. '

pathMTUBottleneckEnd = '''The path MTU bottleneck that fails to
properly report the ICMP "too big" is between %s and your host. '''

pathMTUBottleneckLink = '''The path MTU bottleneck that fails to
properly report the ICMP "too big" is between %s and %s. '''

pathMTUProblem = '''The path between our system and your network does
not appear to report properly when the sender needs to fragment traffic. '''

pathMTUWarning = '''The network path does not reply when it needs to fragment traffic'''

# V6 version

v6SendAndReceiveFragment = '''Your system can send and receive
fragmented traffic with IPv6. '''

v6SendFragmentOnly = '''Your system can send fragmented traffic, but
can not receive fragmented traffic over IPv6. '''

v6ReceiveFragmentOnly = '''Your system can receive fragmented traffic,
but can not send fragmented traffic over IPv6. '''

v6FragmentProblem = '''Your system can not send or receive fragmented
traffic over IPv6. '''

pathMTUV6Send = '''<BR>The path between your network and our system supports
an MTU of at least %i bytes. '''
pathMTUV6Recv = '''The path between our system and your network has an
MTU of %i bytes. '''

pathMTUV6Bottleneck = '  The bottleneck is at IP address %s. '

pathMTUV6BottleneckEnd = '''<BR>The network failed to properly generate an
ICMP6 "too big" message.  The path MTU bottleneck that fails to
properly report the ICMP "too big" is between %s and your host. '''

pathMTUV6BottleneckLink = '''<BR>The network failed to properly generate
an ICMP6 "too big" message.  The path MTU bottleneck that fails to
properly report the ICMP "too big" is between %s and %s. '''

pathMTUV6Problem = '''The path between our system and your network does
not appear to handle fragmented IPv6 traffic properly.  '''

pathMTUV6Warning = '''The path between our system and your network does
not appear to handle fragmented IPv6 traffic properly'''

pathMTUV6NoICMP = '''<BR>The path between our system and your network appears to block ICMP6 "too big" messages. '''

pathMTUV6NoICMPWarning = '''The path between our system and your network appears to block ICMP6 "too big" messages'''


UDPSendFragmentOK = '''<p>The applet was able to send fragmented UDP traffic.</p>'''

UDPSendFragmentFailed = '''<p>The applet was unable to send
fragmented UDP traffic.  The most likely cause is an error in your
network's firewall configuration or NAT.</p>'''

UDPSendMaxFrag = ' The maximum packet successfully sent was %s bytes of payload. '

UDPRecvFragmentOK = '''<p>The applet was able to receive fragmented UDP traffic.</p>'''

UDPRecvFragmentFailed = '''<p>The applet was unable to receive
fragmented UDP traffic.  The most likely cause is an error in
your network's firewall configuration or NAT.</p>'''

UDPRecvMaxFrag = ' The maximum packet successfully received was %s bytes of payload. '

FragmentationWarning = '''Fragmented UDP traffic is blocked'''

MTUWarning = '''There appears to be a path MTU hole'''

MTUSendProblem = '''<BR>The applet was unable to send packets of 1471 bytes of payload (1499 bytes total), which suggests a problem on the path between your system and our server. '''

MTUSendLinux = '''<BR>The applet was able to send a packet of 1471
bytes of payload (1499 bytes total) only on the second try, suggesting your host is running Linux (or other path MTU discovery) on UDP traffic. '''

MTURecvProblem = '''<BR>The applet was unable to receive packets of 1471 bytes of payload (1499 bytes total), which suggests a problem on the path between your system and our server. '''

ReachabilityDNSFirewall = \
'''<p>UDP access to remote DNS servers (port 53) appears to pass
through a firewall or proxy. The applet was unable to transmit an
arbitrary request on this UDP port, but was able to transmit a
legitimate DNS request, suggesting that a proxy, NAT, or firewall
intercepted and blocked the deliberately invalid request.</p>'''

ReachabilityDNSNewID = \
'''<p>A DNS proxy or firewall generated a new request rather than
passing the applet's request unmodified.</p>'''

ReachabilityDNSNewIP = \
'''<p>A DNS proxy or firewall caused the applet's direct DNS request
to be sent from another address.  Instead of your IP address, the
request came from %s.</p>'''

ReachabilityDNSWarning = \
'''The network blocks some or all special DNS types in replies'''

DNSNatWarning = "The NAT's DNS proxy doesn't fully implement the DNS standard"

ReachabilityDNSOK = \
'''All tested DNS types were received OK'''

ReachabilityDNSProblem = \
'''Some or all specialized DNS types checked are blocked by the
network.  The following tested queries were
blocked: <UL>'''

ReachabilityDNSProblemEnd = '</UL>'

ReachabilityDNSProblemEDNS = '<LI>EDNS0 (DNS extensions)</LI>'
ReachabilityDNSProblemAAAA = '<LI>AAAA (IPv6 related) records</LI>'
ReachabilityDNSProblemTXT = '<LI>TXT (text) records</LI>'
ReachabilityDNSProblemICSI = '<LI>RTYPE=169 (deliberately unknown) records</LI>'


DNSNatProblem = \
'''<BR>Some or all specialized DNS types checked are not properly
interpreted by the NAT's DNS proxy.  The following tested queries were
blocked/failed: <UL>'''

DNSNatProblemEnd = '</UL>'

ReachabilityDNSNotExecuted = '''The network you are on blocks direct access to remote DNS servers. '''


ReachabilityEDNSWarning = \
'''The network blocks some or all EDNS replies'''

ReachabilityDNSLarge = \
'''EDNS-enabled requests for large responses are answered
successfully. '''

ReachabilityDNSLargeBlocked = \
'''EDNS-enabled requests for large responses remain unanswered.  This
suggests that a proxy or firewall is unable to handle large extended
DNS requests or fragmented UDP traffic. '''

ReachabilityDNSMedium = \
'''EDNS-enabled requests for medium-sized responses are answered successfully. '''

ReachabilityDNSMediumBlocked = \
'''EDNS-enabled requests for medium-sized responses remain unanswered.
This suggests that a proxy or firewall is unable to handle extended
DNS requests or DNS requests larger than 512 bytes. '''

ReachabilityDNSSmall = \
'''EDNS-enabled requests for small responses are answered
successfully. '''

ReachabilityDNSSmallBlocked = \
'''EDNS-enabled requests for small responses remain unanswered.  This
suggests that a proxy or firewall is unable to handle extended DNS
requests. '''

ReachabilityDNSUDPOK = 'Direct UDP access to remote DNS servers (port 53) is allowed. '

ReachabilityDNSUDPFailed = '''<p>Direct UDP access to remote DNS servers
(port 53) is blocked.</p> <p>The network you are using appears to enforce
the use of a local DNS resolver.</p>'''

ReachabilityDNSUDPWrongData = '''Direct UDP connections to remote DNS
servers (port 53) succeed, but do not receive the expected content. '''

ReachabilityDNSTCPOK = 'Direct TCP access to remote DNS servers (port 53) is allowed. '

ReachabilityDNSTCPFailed = '''<p>Direct TCP access to remote DNS servers
(port 53) is blocked.</p> <p>The network you are using appears to enforce
the use of a local DNS resolver.</p>'''

ReachabilityDNSTCPWrongData = '''Direct TCP connections to remote DNS
servers (port 53) succeed, but do not receive the expected content. '''


natDNSProxy = '''Your NAT has a built-in DNS proxy. '''
natDNSNoProxy = '''We were unable to detect a DNS proxy associated with your NAT. '''

natDNS2Wire = '''You appear to be using a NAT/gateway manufactured by 2Wire. '''

ReachabilityInvalidReply = 'The applet received the following reply instead of our expected header: '

# Generic phrasing for those protocols that don't require special
# commenting.  No named substitution for now since code change would
# be fairly substantial. :( --cpk
ReachabilityTCPServiceOK = '''Direct TCP access to remote %s servers (port %s)
is allowed. '''
ReachabilityTCPServiceFailed = '''Direct TCP access to remote %s servers (port 
%s) is blocked. '''

ReachabilityServiceV6OK = '''<p>This service is reachable using IPv6.</p>'''
ReachabilityServiceV6Failed = '''<p>This service is blocked when using IPv6.</p>'''
ReachabilityServiceV6Proxied = '''<p>This service is proxied when accessed using using IPv6.</p>'''

ReachabilityServiceV6ProxiedData = '''<BR>An unexpected response was
received using IPv6.  Instead of our expected data, the applet
received "%s". '''



ReachabilityHTTPFailed = '''<p>Direct TCP access to remote HTTP
servers (port 80) is blocked.</p> <p>This network appears to enforce
the use of a mandatory HTTP proxy.</p>'''

ReachabilityHTTPFailedNote = '''Direct TCP access to remote HTTP
servers appears to be blocked, as the applet was not able to make a
direct request to our server.  Thus this network appears to enforce
the use of a mandatory HTTP proxy configured in the web browser.  As a
result, the low level HTTP tests, which search for the effects of
otherwise unadvertised proxies in the network, rather than proxies
configured in the browser, are not executed. '''

ReachabilityUDPServiceOK = """Direct UDP access to remote %s servers
(port %s) is allowed."""
ReachabilityUDPServiceFailed = """Direct UDP access to remote %s
servers (port %s) is blocked."""
ReachabilityUDPServiceWrongData = """Direct UDP flows to remote %s
servers (port %s) succeed, but do not receive the expected content."""

ReachabilitySlammerFailed = '''<p>Direct UDP access to remote MSSQL
servers (port 1434) is blocked.</p><p>
This is most likely due to a filtering rule against the Slammer worm.</p>'''

ReachabilityTCPServiceFailedLocal = '''<p>Direct TCP access to remote
%s servers (port %s) is blocked.</p><p>This is probably for security
reasons, as this protocol is generally not designed for use outside
the local network.</p>'''

ReachabilityTCPServiceWrongData = '''Direct TCP connections to remote %s
servers (port %s) succeed, but do not receive the expected content. '''

ReachabilityFTPServiceWrongData = '''<p>Direct TCP connections to remote
%s servers (port %s) succeed, but do not receive the expected
content.</p>
<p>This is most likely due to the way a NAT or firewall handles
FTP traffic, as FTP causes unique problems when developing NATs and
firewalls.  This is most likely benign.</p>'''

ReachabilityFTPServiceFailed = '''<p>Direct TCP connections to remote
%s servers (port %s) failed.</p>
<p>This is commonly due to how a NAT or firewall handles
FTP traffic, as FTP causes unique problems when developing NATs and
firewalls.</p>'''

TerminatedConnection = '''
<p>The applet received an empty response instead of our normal
banner.  This suggests that a firewall, proxy, or filter initially
allowed the connection and then terminated it, either because it did
not understand our server's reply or decided to block the service.
</p>'''

ReachabilityDifferentPath = '''<p>The connection succeeded but came from
a different IP address than we expected.  Instead of the expected IP
address, we received this request from %s.</p>'''

ReachabilitySMTPOK = 'Direct TCP access to remote SMTP servers (port 25) is allowed. '

ReachabilitySMTPFailed = '''<p>Direct TCP access to remote SMTP servers
(port 25) is prohibited.</p> <p>This means you cannot send email via SMTP
to arbitrary mail servers. Such blocking is a common countermeasure
against malware abusing infected machines for generating spam. Your
ISP likely provides a specific mail server that is permitted. Also,
webmail services remain unaffected.</p>'''

ReachabilitySMTPWrongData = '''<p>Direct TCP access to remote SMTP
servers (port 25) succeeds, but does not return the expected content.
</p> <p>This suggests that your network enforces a mandatory SMTP proxy
which may or may not allow you to send email directly from your
system.  This is probably a countermeasure against malware abusing
infected machines for generating spam.  You ISP also likely provides a
specific mail server that is permitted.  Also, webmail services remain
unaffected.</p>'''

LatencyLoss = 'Latency: %ims Loss: %3.1f%%'

LatencyHeader = '''<p>This test measures the network latency (delay) &mdash; the round 
trip time (RTT) &mdash; measured in milliseconds that it takes a message to go from 
your computer to our server and back when there is no other traffic 
occurring. The amount of time this takes can depend on a variety of 
factors, including the distance between your system and our server
as well as the quality of your Internet connection.</p>'''

LatencyGood = '''The round-trip time (RTT) between your computer and
our server is %i msec, which is good. '''

LatencyFair = '''The round-trip time (RTT) between your computer and
our server is %i msec, which is somewhat high.  This may be due to a
variety of factors, including distance between your computer and our
server, a slow network link, or other network traffic. '''


Duplication0 = 'During this test, the applet observed no duplicate packets. '
Duplication1 = 'During this test, the applet observed one duplicate packet. '
DuplicationN = 'During this test, the applet observed %s duplicate packets. '

Reordering0 = 'During this test, the applet observed no reordered packets. '
Reordering1 = 'During this test, the applet observed one reordered packet. '
ReorderingN = 'During this test, the applet observed %s reordered packets. '

BackgroundHealthNoTransients = 'no transient outages'
BackgroundHealthStatus = '%i transient outages, longest: %2.1f seconds'

BurstHeader = '''During most of Netalyzr's execution, the applet
continuously measures the state of the network in the background,
looking for short outages. '''

BurstNone = '''  During testing, the applet observed no such outages. '''

BurstBad = '''  During testing, the applet observed %(count)i such outages.
The longest outage lasted for %(length)2.1f seconds.  This suggests a general
problem with the network where connectivity is intermittent.  This
loss might also cause some of Netalyzr's other tests to produce
incorrect results. '''

TCPLatencyGood = '''The time it takes your computer to set up a TCP
connection with our server is %i msec, which is good. '''

TCPLatencyFair = '''The time it takes your computer to set up a TCP
connection with our server is %i msec, which is somewhat high.  This
may be due to a variety of factors, including distance between your
computer and our server, a slow network link, or other network
traffic. '''

TCPLatencyMismatch = '''Setting up a TCP connection to a previously
uncontacted port takes %(first)i msec, while subsequent connections are
established in %(next)i msec.  This discrepancy could be due to a transient
network failure or a host-based firewall that prompts users to
authorize new connections generated by the applet. '''

# In the aberrations, even poor latency/loss will just be classed as a
# minor to moderate abnormality.

LatencyNotMeasuredWarning = '''Network latency could not be measured'''

LatencyWarning = '''The measured network latency was somewhat high'''

TCPLatencyWarning = '''The measured time to set up a TCP connection was somewhat high'''

LossWarning = '''The measured packet loss was somewhat high'''

BurstWarning = '''The network measured bursts of packet loss'''

LatencyLossWarning = '''The measured network latency and packet loss
were somewhat high'''

LatencyNotMeasured = '''We were unable to measure your network latency,
because no measurement packets could be transmitted. '''

LatencyPoor = '''The round-trip time (RTT) between your computer and
our server is %i msec, which is quite high.  This may be due to a
variety of factors, including a significant distance between your
computer and our server, a particularly slow or poor network link, or
problems in your network. '''

TCPLatencyPoor = '''The time it takes for your computer to set up a
TCP connection with our server is %i msec, which is quite high.  This
may be due to a variety of factors, including a significant distance
between your computer and our server, a particularly slow or poor
network link, or problems in your network. '''

LossHeader = '''<p>At the same time, we also measure "packet loss", 
the number of packets that are sent but not received. Packet loss 
may be due to many factors, ranging from poor connectivity (e.g., at
a wireless access point), internal network trouble (stress or
misconfiguration), or significant load on our server.</p>'''

LossPerfect = 'We recorded no packet loss between your system and our server. '

LossGood = '''<P>We recorded a packet loss of %2.1f%%.  This loss rate is 
within the range commonly encountered and not usually inducing significant
performance problems. '''

### It would be good to diagnose loss due to server load, which seems
# we can try to do by having the server report to the client just how
# many requests/sec or whatever it's currently dealing with. - VP

# Hmm, good idea.  -NW

LossFair = '''We recorded a packet loss of %2.1f%%.  
This loss rate can result in noticeable performance problems.  It could
be due either to 
significant load on our servers due to a large number of visitors, or 
problems with your network. '''

LossPoor = '''We recorded a packet loss of %2.0f%%.  
This loss is very significant and will lead to serious performance
problems.  It could be due either to very high 
load on our servers due to a large number of visitors, or problems in 
your network. '''

LossServer = '''  Of the packet loss, at least %2.1f%% of the packets
appear to have been lost on the path from your computer to our
servers. '''

LossNoServer = ''' All the packet loss appears to have occurred on the
path from our server to your computer. '''

# E.g. ">10 Mbps"
MaxBandwidthString = "&gt;%(num)s %(unit)s"

BandwidthUplink = 'Uplink'
Bandwidthuplink = 'uplink'
BandwidthDownlink = 'Downlink'
Bandwidthdownlink = 'downlink'
BandwidthSending = 'sending'
BandwidthReceiving = 'receiving'

BandwidthWarning = '''Network bandwidth may be low'''

BandwidthNoRecvWarning = '''None of the server's bandwidth measurement
packets arrived at the client'''

BandwidthHeader = '''This test measures network transmission speed
("bandwidth") by sending and receiving a large number of packets. '''

BandwidthNoRecv = '''None of the bandwidth measurement packets sent
between the server and client arrived at the client, which prevented
us from measuring the available bandwidth. One possible reason for
this is dynamic filtering by access gateway devices.  Another
possibility is simply a transient error. '''

BandwidthNoRecvTest = '''None of the bandwidth measurement packets
sent between the server and client arrived at the client when testing
the %s, which prevented us from measuring the available bandwidth. One
possible reason for this is dynamic filtering by access gateway
devices.  Another possibility is simply a transient error. '''

# Example: dir="Uplink", dir2="uplink", operation="sending",
# bw="1Mbps".
BandwidthGood = '''Your %(dir)s: We measured your %(dir2)s's
%(operation)s bandwidth at %(bw)s.  This level of bandwidth works well
for many users. '''

BandwidthFair = '''Your %(dir)s: We measured your %(dir2)s's
%(operation)s bandwidth at %(bw)s.  This rate could be considered
somewhat slow, and may affect your user experience if you perform
large transfers. '''

BandwidthPoor = '''Your %(dir)s: We measured your %(dir2)s's
%(operation)s bandwidth at %(bw)s.  This rate could be considered
quite slow, and will affect your user experience if you perform large
transfers. '''

BufferUplinkMS = 'Uplink %i ms'
BufferUplinkGood = 'Uplink is good'
BufferDownlinkMS = 'Downlink %i ms'
BufferDownlinkGood = 'Downlink is good'
BufferUploads = 'uploads'
BufferDownloads = 'downloads'
BufferUploading = 'uploading'
BufferDownloading = 'downloading'

BufferWarning = '''Network packet buffering may be excessive'''

BufferHeader = '''<P>One little considered but important part of 
your network experience is the amount of buffering in your network. When 
you conduct a full-rate download or upload, the associated network 
buffer can become full, which affects the responsiveness of your
other traffic.</P>'''

BufferNoRecv = '''None of the buffer measurement packets sent by
the server arrived at the client, which prevented us from measuring the 
available buffer size. One possible reason for this is dynamic filtering
by access gateway devices. '''

BufferUnableToMeasure = '''We were not able to produce enough traffic
to load the %(dir)s buffer, or the %(dir)s buffer is particularly
small. You probably have excellent behavior when %(op)s files and
attempting to do other tasks. '''

BufferGood = '''We estimate your %(dir)s as having %(rtt).0f msec of buffering.
This level may serve well for maximizing speed while minimizing the
impact of large transfers on other traffic. '''

# Example: dir="downlink", rtt="10ms", trans="downloads"
BufferFair = '''We estimate your %(dir)s as having %(rtt).0f msec of buffering.
This level can in some situations prove somewhat
high, and you may experience degraded performance when performing
interactive tasks such as web-surfing while simultaneously conducting
large %(trans)s.  Real-time applications, such as games or audio chat, may
also work poorly when conducting large %(trans)s at the same time. '''

BufferPoor = '''We estimate your %(dir)s as having %(rtt).0f msec of buffering.
This is quite high, and you may experience
substantial disruption to your network performance when performing
interactive tasks such as web-surfing while simultaneously conducting
large %(trans)s.  With such a buffer, real-time applications such as games or
audio chat can work quite poorly when conducting large %(trans)s at the same time. '''

### VP: this is where I currently am

DNSRestrictedWrongName = '''The name returned by your DNS server 
for this system DOES NOT MATCH this server\'s IP address.  Thus, the 
DNS server you are using is returning wrong results. '''

DNSRestrictedGood = '''We can successfully look up a name which
resolves to the same IP address as our webserver.  This means we are
able to conduct many of the tests on your DNS server. '''

DNSRestrictedFailed = \
'''Restricted DNS lookup test failed to complete. '''

DNSUnrestrictedGood = \
'''We can successfully look up arbitrary names from within the
Java applet.  This means we are able to conduct all test on your DNS
server. '''

DNSUnrestrictedProhibited = \
'''Due to your current Java security parameters, we are not able to
look up arbitrary names from within the Java applet.  This prevents
us from conducting all the checks on your DNS server. '''

DNSUnrestrictedFailed = \
'''Unable to lookup a name not associated with our server. '''


AddressProxyWarning = '''An HTTP proxy was detected based on address difference'''

HeaderProxyWarning = '''An HTTP proxy was detected based on added or changed HTTP traffic'''

HeaderProxyCertProblem = '''An HTTP proxy was detected which may be vulnerable to attack. '''

MalformedProxyWarning = '''The detected HTTP proxy blocks malformed HTTP requests'''

TransparentCacheBad = '''A detected in-network HTTP cache incorrectly caches information'''

TransparentCacheWarning = '''A detected in-network HTTP cache exists in your network'''




AddressProxyMalformed = '''The URL used for this test was malformed. '''

AddressProxyNone = '''There is no explicit sign of HTTP proxy use based on IP address. '''

AddressProxyFound = '''Your HTTP connections come from %(proxy)s%(detail)s while
non-HTTP connections originate from %(ip)s, indicating that your HTTP
traffic is passing through a proxy. '''

AddressProxyManual = '''Your browser's HTTP connections come from %(proxy)s%(detail)s while
non-browser HTTP connections originate from %(ip)s, indicating that your web browser
has a proxy manually configured. '''

AddressProxyManualAdditional = '''Furthermore, your global IP address for 
non-HTTP traffic is %s, which means that your HTTP traffic goes through an 
additional proxy besides the one you configured'''

HeaderProxyNone = '''No HTTP header or content changes hint at the presence of a proxy. '''

HeaderProxyAddrOnly = \
"""The HTTP proxy did not modify any headers or content."""

HeaderProxyVia = '''<P>A "Via" header of the HTTP response showed the
presence of an HTTP proxy.  We identified it at %(host)s, port
%(port)s.</P>'''

HeaderProxyXcache = '''<P>An "X-Cache-Lookup" header in the HTTP
response showed the presence of an HTTP proxy.  We identified it at
%(host)s, port %(port)s.</P>'''

HeaderProxyChanges = '''<P>Changes to headers or contents sent between
the applet and our HTTP server show the presence of an otherwise
unadvertised HTTP proxy.</P>'''

HeaderProxyAddedRequest = '''<P>The following headers were added by 
the proxy:</P>'''

HeaderProxyRemoved = '''<P>The following headers were removed by the proxy:</P>'''

HeaderProxyReordered = '''<P>The detected proxy reordered the headers
sent from the server.</P>'''

HeaderProxyChanged = '''<P>The following headers had their
capitalization modified by the proxy:</P>'''

HeaderCookieRemoved = '''<P>The HTTP proxy removed the cookie from the
connection.</P>'''

HeaderCookieChanged = '''<P>The HTTP proxy added or changed the cookie
we set.  We received "%s", when we expected "netAlizEd=BaR".</P>'''

JSCookieChanged = '''<P>The HTTP proxy added an additional tracking
cookie which we were able to observe in JavaScript running on our test
page.  We observed the following additional cookies:</P>'''

HeaderProxyAddedResponse = '''<P>The following headers were added by 
the proxy to HTTP responses:</P>'''

MalformedTestOK = '''Deliberately malformed HTTP requests arrive at our server
unchanged.  We are not able to detect a proxy along the path to our
server using this method. '''

MalformedTestProxyOK = \
'''Deliberately malformed HTTP requests arrive at our server unchanged.
Thus, the proxies along your path are able to transparently forward
invalid HTTP traffic. '''

MalformedTestBad = \
'''Deliberately malformed HTTP requests do not arrive at our server.
This suggests that an otherwise undetected proxy exists along the
network path.  This proxy was either unable to parse or refused to
forward the deliberately bad request. '''

MalformedTestProxyBad = \
'''Deliberately malformed HTTP requests do not arrive at our server.
This suggests that the proxy we detected on your network path was
either unable to parse or refused to forward the deliberately bad
request. '''

ProxyCert = \
'''<P>The detected HTTP proxy may cause your traffic to be vulnerable
to CERT <A HREF="http://www.kb.cert.org/vuls/id/435052">Vulnerability
Note 435052</A>.  An attacker might be able to use this vulnerability
to attack your web browser.</P>'''

ProxyTranscodes = \
'''<P>The detected HTTP proxy changed images that were sent from our server.</P>'''

ProxyChanges = \
'''<P>The detected HTTP proxy changed either the headers the applet sent or the HTTP response from the server.  We have captured the changes for further analysis.</P>'''

CacheSU = 'Strongly uncacheable'
CacheWU = 'Weakly uncacheable'
CacheWC = 'Weakly cacheable'
CacheSC = 'Strongly cacheable'

CacheURLMalformed = 'One of the test URLs was malformed. '
CacheImageError = 'One of the test images could not be downloaded. '

CacheDetected = \
'''We detected the presence of an in-network transparent HTTP cache
that caches data which was directly requested by the applet. '''

CacheWasCached = \
'''%s data was cached between you and our server, even when the data
was requested directly and explicitly.  This suggests that there is an
HTTP cache in the network which examines and caches web traffic. '''

CacheIsError = \
'''  Since this content was not supposed to be cached, the HTTP cache is probably operating incorrectly. '''

CacheWasNotCached = \
'''%s data was not cached between you and our server when it was
explicitly fetched. '''

CacheAllUncached = \
'''There is no suggestion that a transparent HTTP cache exists in your network. '''

JSUnavailable = \
'''JavaScript is not enabled for the Netalyzr site. '''

JSFramedWarning = \
'''Web content is jailed into HTML frames'''

JSFramed = \
'''The applet was run from within a frame.  Since our launch page
specifically is designed to remove itself from any frames, some
process must have reintroduced the frame. '''

JSUnframed = \
'''The applet was not run from within a frame. '''

JSCookieStripped = \
'''Your web browser does not store cookies. '''

JSCookieList = \
'''Your web browser reports the following cookies for our web page: '''

JSCookieBerkeley = '(set by some other web page at berkeley.edu)'
JSCookieServer = '(set by our server)'
JSCookieNoScript = '(probably set by NoScript)'


DNSLookupLatency = 'Lookup latency %ims'
DNSReqRecvFrom = "  We sent it a DNS request and our server received it from %s."

DNS0x20 = '''Your resolver uses 0x20 randomization. '''

DNS0x20passthrough = '''Your resolver does not use 0x20 randomization, but will pass names in a case-sensitive manner. '''

DNSno0x20 = '''Your resolver does not use 0x20 randomization. '''

DNSANY = '''Your resolver is using QTYPE=ANY for default queries. '''

DNSnotANY = '''Your resolver is using QTYPE=A for default queries. '''

IPv6Enabled = '''Your web browser is able to fetch an image using
IPv6.  Your network is IPv6 enabled. '''

IPv6Unenabled = '''Your web browser was unable to fetch an image using IPv6. '''

DNSFailoverOK = '''Your resolver correctly uses TCP requests when necessary. '''

DNSFailoverBad = '''Your resolver is incapable of using TCP to process requests when necessary. '''

DNSFailoverIgnored = '''Your resolver ignored the response suggesting it should retry with TCP. '''

DNSSECOK = '''No transport problems were discovered which could affect
the deployment of DNSSEC. '''

DNSSECBad = '''Your DNS resolver may have significant
transport-problems with the upcoming DNSSEC deployments.  '''

DNSSECTCPBad = '''The resolver is incapable of falling back to TCP.  '''
DNSSECFragBad = '''The resolver is incapable of handling UDP fragmentation.  '''
DNSSECSmallBad = '''The resolver is incapable of handling a UDP
response greater than 512B. '''

DNSSECTransportWarning = '''The DNS resolver may have problems with DNSSEC'''

DNSAAAA = '''Your host or resolver also performs IPv6 queries in addition to IPv4 queries. '''

DNSnotAAAA = '''Your resolver is not automatically performing IPv6 queries. '''

DNSGlueDanger = '''Your DNS server accepts unusual glue records'''

DNSNSDanger = '''Your DNS server accepts bad glue records for nameservers'''

DNSCnameDanger = '''Your DNS server accepts unusual glue records for CNAMEs'''

DNSLookupDanger = '''We received unexpected and possibly dangerous results when looking up important names'''

DNSConflickerDanger = '''Your computer may be infected by the Conficker worm'''

DNSWildcardDanger = '''Your DNS resolver returns results even when no such server exists'''

DNSLookupBoth = '''Your ISP's DNS resolver requires %(t1)i msec to conduct
an external lookup, and %(t2)i msec to lookup an item in the cache. '''

DNSLookupServer = \
''' It takes %i msec for your ISP's DNS resolver to lookup a name on
our server. '''

DNSLookupUncached = \
'''Your ISP's DNS resolver requires %i msec to conduct an external lookup. '''

DNSLookupSlow = \
'''<BR>This is particularly slow, and you may see significant performance degradation as a result. '''

DNSV6Server = \
'''Your ISP's DNS server is capable of fetching records using IPv6. '''

DNSV6ServerFailed = \
'''Your ISP's DNS server cannot use IPv6. '''

DNSSlowWarning = \
'''Your ISP's DNS server is slow to lookup names'''

DNSTTL0Cached = \
'''Your ISP's DNS resolver does not respect a TTL of 0 seconds. '''

DNSTTL0Uncached = \
'''Your ISP's DNS resolver respects a TTL of 0 seconds. '''


DNSTTL1Cached = \
'''Your ISP's DNS resolver does not respect a TTL of 1 seconds. '''

DNSTTL1Uncached = \
'''Your ISP's DNS resolver respects a TTL of 1 seconds. '''

DNSGlueNone = \
'''Your ISP's DNS resolver does not accept generic additional (glue) records &mdash; good. '''

DNSGlueExact = \
'''Your ISP's DNS resolver accepts generic (glue) records when they
are in the same domain requested. '''

DNSGlueInternal = \
'''Your ISP's DNS resolver accepts generic glue records located in
subdomains of the queried domain. '''

DNSGlueExternal = \
'''The DNS resolver you are using appears to accepts 'out-of-bailiwick' glue
records!  This is very unusual. '''

DNSNSGlueNone = \
'''Your ISP's DNS resolver does not accept additional (glue) records
which correspond to nameservers. '''

DNSNSGlueExact = \
'''Your ISP's DNS resolver accepts additional (glue) records for
nameservers when they are in the same domain requested. '''

DNSNSGlueInternal = \
'''Your ISP's DNS resolver accepts additional (glue) records for
nameservers located in subdomains of the queried domain. '''

DNSNSGlueExternal = \
'''The DNS resolver you are using appears to accepts 'out-of-bailiwick' glue
records for nameservers!  This is very unusual. '''


DNSCnameNone = \
'''Your ISP's DNS resolver does not follow CNAMEs. '''

DNSCnameNS = \
'''Your ISP's DNS resolver follows CNAMEs for nameservers in the same domain. '''

DNSCnameExact = \
'''Your ISP's DNS resolver follows CNAMEs when it is in the same domain. '''

DNSCnameInternal = \
'''Your ISP's DNS resolver follows CNAMEs when it is in a subdomain of
the queried domain. '''

DNSCnameExternal = \
'''Your ISP's DNS resolver follows CNAMEs regardless of their
location.  This is very unusual. '''

DNSCnameExternal2 = \
'''Your ISP's DNS resolver follows CNAMEs regardless of their
location, but only after having learned that this nameserver is valid
for the other domain.  This is very unusual. '''

DNSTableHeadline = \
'''<tr>
  <th class="tblt" width="39%">Name</th>
  <th class="tblt" width="22%">IP Address</th>
  <th class="tblt" width="39%">Reverse Name/SOA</th>
</tr>
'''

DNSErrorTableLine = \
'''<tr class="etbl%d">
  <td>%s</td>
  <td>%s</td>
  <td>%s</td>
</tr>
'''


DNSErrorTableLineSOA = \
'''<tr class="etbl%d">
  <td>%s</td>
  <td>%s</td>
  <td>SOA: %s</td>
</tr>
'''

DNSWarningTableLine = \
'''<tr class="wtbl%d">
  <td><a class="plain" href="http://%s" target="_blank">%s</a></td>
  <td>%s</td>
  <td>X</td>
</tr>
'''


DNSWarningTableLineSOA = \
'''<tr class="wtbl%d">
  <td><a class="plain" href="http://%s" target="_blank">%s</a></td>
  <td>%s</td>
  <td>SOA: %s</td>
</tr>
'''


DNSWarningTableLineExpected = \
'''<tr class="stbl%d">
  <td><a class="plain" href="http://%s" target="_blank">%s</a></td>
  <td>%s</td>
  <td>X</td>
</tr>
'''


DNSWarningTableLineExpectedSOA = \
'''<tr class="stbl%d">
  <td><a class="plain" href="http://%s" target="_blank">%s</a></td>
  <td>%s</td>
  <td>SOA: %s</td>
</tr>
'''

DNSSuccessTableLineSOA = \
'''<tr class="stbl%d">
  <td><a class="plain" href="http://%s" target="_blank">%s</a></td>
  <td>%s</td>
  <td>X (<a class="plain" href="http://%s" target="_blank">%s</a>)</td>
</tr>
'''

DNSSuccessTableLine = \
'''<tr class="stbl%d">
  <td><a class="plain" href="http://%s" target="_blank">%s</a></td>
  <td>%s</td>
  <td>%s</td>
</tr>
'''

ignoredNames = ''

DNSBadReverse0 = "<p>No popular names have a significant anomaly."
DNSBadReverse1 = "<p>One popular name has a significant anomaly."
DNSBadReverseN = "<p>%s popular names have a significant anomaly."
DNSBadReverseAddl = ''' The ownership suggested by the reverse name
lookup does not match our understanding of the original name.  This
could be caused by an error somewhere in the domain information, deliberate blocking or redirection of a site using DNS, or it
could be that your ISP's DNS Server is acting as a DNS
"Man-in-the-Middle".</p>
'''

DNSBadReverseHTTPNote = \
'''<p>We attempted to download HTTP content from the IP addresses that
your ISP's DNS server returned to you for these names. Where the
download succeeded, you can click on the IP address in the table below
to download a compressed file containing an HTTP session transcript.</p>

<p><b>Note!</b> The session content is potentially harmful to your
computer when viewed in a browser, so use caution when examining
it.</p>
'''


DNSBadReverseNotorious0 = "No popular name has a mild anomaly."
DNSBadReverseNotorious1 = "One popular name has a mild anomaly."
DNSBadReverseNotoriousN = "%s popular names have a mild anomaly."
DNSBadReverseNotoriousAddl = ''' The ownership suggested by the
reverse name lookup does not match our understanding of the original
name.  The most likely cause is the site's use of a Content Delivery
Network.

<script language="javascript" type="text/javascript">
<!--
function toggle2() {
var ele = document.getElementById("toggleText2")
var text = document.getElementById("displayText2");

if(ele.style.display == "block") {
ele.style.display = "none";
text.innerHTML = "Show all names";
}

else {
ele.style.display = "block";
text.innerHTML = "Hide all names";
}
} 
-->
</script>

<script language="javascript" type="text/javascript">
<!--
document.write('<a href="javascript:toggle2();" id="displayText2">Show all names<\/a>. ')
document.write('<div id="toggleText2" style="display: none;">');
-->
</script>'''

DNSBadReverseNotoriousEnd = \
'''
<script language="javascript" type="text/javascript">
<!--
document.write('<\/div>');
-->
</script>
'''


DNSNoReverseNotoriousEnd = \
'''
<script language="javascript" type="text/javascript">
<!--
document.write('<\/div>');
-->
</script>
'''

DNSBadReverseOpenDNSIntro = \
'''You appear to be using OpenDNS as your DNS resolver.  OpenDNS acts
as a Man-in-the-Middle for some servers, returning the address of one
of their servers that acts as an intermediary, rather than the final
result. '''

DNSBadReverseOpenDNS0 = "As a result, no lookup appears to be anomalous."
DNSBadReverseOpenDNS1 = "As a result, one lookup appears to be anomalous."
DNSBadReverseOpenDNSN = "As a result, %s lookups appear to be anomalous."

DNSBadNoReverse0 = "<p>No popular name has a moderate anomaly: "
DNSBadNoReverse1 = "<p>One popular name has a moderate anomaly: "
DNSBadNoReverseN = "<p>%s popular names have a moderate anomaly: "
DNSBadNoReverseAddl = ''' we are unable to find a reverse name
associated with the IP address provided by your ISP's DNS server,
although we expected to find a name.  This is most likely due to a
slow responding DNS server.  If you rerun Netalyzr and see this
condition remain, it could be due to a misconfiguration on the part of
the domain owner, deliberate blocking using DNS, or your DNS server could be misconfigured or enabling
a Man-in-the-Middle attack.</p>'''

DNSBadNoReverseNotorious0 = "No popular name has a mild anomaly: "
DNSBadNoReverseNotorious1 = "One popular name has a mild anomaly: "
DNSBadNoReverseNotoriousN = "%s popular names have a mild anomaly: "
DNSBadNoReverseNotoriousAddl = ''' we are unable to find a reverse
name associated with the IP address provided by your ISP's DNS server.
This is most likely due to a slow responding DNS server or
misconfiguration on the part of the domain owner.

<script language="javascript" type="text/javascript">
<!--
function toggle3() {
var ele = document.getElementById("toggleText3")
var text = document.getElementById("displayText3");

if(ele.style.display == "block") {
ele.style.display = "none";
text.innerHTML = "Show all names";
}

else {
ele.style.display = "block";
text.innerHTML = "Hide all names";
}
} 
-->
</script>

<script language="javascript" type="text/javascript">
<!--
document.write('<a href="javascript:toggle3();" id="displayText3">Show all names<\/a>. ')
document.write('<div id="toggleText3" style="display: none;">');
-->
</script>'''

DNSLookupFailed = \
'''The most likely cause for failed forward lookups is a transient
network issue. '''

DNSLookupConflicker = \
'''The following names were not successfully looked up by the applet.
Because these names are all security-related companies, you may be
infected with the <A
HREF="http://www.confickerworkinggroup.org/wiki/">Conficker</A> worm. '''


DNSNotorious = \
'''For the following names, the ownership
suggested by the reverse name lookup does not match the original
name. These domains are consistently showing this behavior, so the
anomalies are unlikely to be harmful. '''

DNSNotoriousNoReverse = \
'''For the following names, the ownership
suggested by the reverse name lookup does not match the original
name. These domains are consistently showing this behavior, so the
anomalies are unlikely to be harmful. '''

DNSReverseOK = \
'''%(num1)s of %(num2)s popular names were resolved successfully. %(msg)s

<script language="javascript" type="text/javascript">
<!--
function toggle() {
var ele = document.getElementById("toggleText")
var text = document.getElementById("displayText");

if(ele.style.display == "block") {
ele.style.display = "none";
text.innerHTML = "Show all names";
}

else {
ele.style.display = "block";
text.innerHTML = "Hide all names";
}
} 
-->
</script>

<script language="javascript" type="text/javascript">
<!--
document.write('<a href="javascript:toggle();" id="displayText">Show all names<\/a>. ')
document.write('<div id="toggleText" style="display: none;">');
-->
</script>

In the following table reverse lookups that failed but for which a
Start Of Authority (SOA) entry indicated correct name associations are
shown using an "X", followed by the SOA entry. Absence of both IP
address and reverse name indicates failed forward lookups.
'''

DNSReverseOKEnd = '''
<script language="javascript" type="text/javascript">
<!--
document.write('<\/div>');
-->
</script>
'''

DNSResolverSuccess = "resolves to %s"
DNSResolverFailure = "does not resolve"
DNSResolver = \
'''The IP address of your ISP's DNS Resolver is %(ip)s, which %(result)s. '''

DNSResolverAdditional = '  Additional nameservers observed for your host: '

DNSRandProblem = '''No DNS Port Randomization'''

DNSRandOK = \
'''Your ISP's DNS resolver properly randomizes its local port number. '''

DNSRandPorts = \
    '''<p>The following graph shows DNS requests on the x-axis and the
detected source ports on the y-axis.</p> '''

DNSRandBad = \
'''<p>Your ISP's DNS resolver does not randomize its local port
number.  This means your ISP's DNS resolver is probably vulnerable to
DNS cache poisoning, which enables an attacker to intercept and modify
effectively all communications of anyone using your ISP.</p> <p>We
suggest that, if possible, you immediately contact your network
provider, as this represents a serious vulnerability.</p>
'''

DNSWildcardServfail = \
'''<P>Another problem with the DNS server is its response to a server
failure.  Instead of properly returning an error when it cannot contact
the DNS authority, the DNS server returns an address of %s.  Since
transient failures are quite common this can be significantly
disruptive, turning a transient failure into a wrong answer without
any notification to the application doing the name lookup.</P>'''

DNSWildcardOK = \
'''Your ISP correctly leaves non-resolving names untouched. '''

DNSWildcardBad = \
'''<P>Your ISP's DNS server returns IP addresses even for domain names
which should not resolve.  Instead of an error, the DNS server returns
an address of %(addr)s, which %(resolving)s. %(nxlink)s</P>

<P>There are several possible explanations for this behavior.  The
most likely cause is that the ISP is attempting to profit from
customer's typos by presenting advertisements in response to bad
requests, but it could also be due to an error or misconfiguration in
the DNS server.</P>

<P>The big problem with this behavior is that it can potentially break
any network application which relies on DNS properly returning an
error when a name does not exist.</P>

<P>The following lists your DNS server's behavior in more detail.</P>
'''

DNSWildcardBadOpenDNS = \
'''<P>You appear to be using OpenDNS.  OpenDNS, by
default, deliberately returns addresses even for domain names which
should not resolve.  Instead of an error, the DNS server returns an
address of %(addr)s, which %(resolving)s. %(nxlink)s</P>

<P>This is central to OpenDNS's business model.  In order to support
an otherwise free service, OpenDNS presents the users with
advertisements whenever they make a typo in their web browser.  You
can disable this behavior through the OpenDNS <A
HREF="https://www.opendns.com/dashboard">Dashboard</A>.</P>

<P>The big problem with this behavior is that it can potentially break
any network application which relies on DNS properly returning an
error when a name does not exist.</P>

<P>The following lists your DNS server's behavior in more detail.</P>
'''


DNSWildcardBadUltraDNS = \
'''<P>You appear to be using UltraDNS and/or DNS Advantage.  This service,
by default, deliberately returns addresses even for domain names which
should not resolve.  Instead of an error, the DNS server returns an
address of %(addr)s, which %(resolving)s. %(nxlink)s</P>

<P>This is central to UltraDNS's business model.  In order to support
an otherwise free service, UltraDNS presents the users with
advertisements whenever they make a typo in their web browser.

<P>The big problem with this behavior is that it can potentially break
any network application which relies on DNS properly returning an
error when a name does not exist.</P>

<P>The following lists your DNS server's behavior in more detail.</P>
'''

DNSWildcardShowLink = \
'''You can inspect the resulting HTML content <a href="/uploaded/id=%s/key=nxpage">here</a>. '''

DNSWildcardMap = '%(dom)s is mapped to %(ip)s. '
DNSWildcardOKName = '%(dom)s is correctly reported as an error. '

DNSv6LookupOK = 'Your system can successfully look up IPv6 addresses. '
DNSv6LookupNone = 'Your system does not look up IPv6 addresses by default. '

DNSv6LookupBad = '''The DNS resolver you are using deliberately
manipulates results.  This can prove problematic, as you will be
unable to contact an IPv6-only site: the DNS resolver is giving
incorrect results for a system which has only an IPv6 address.  We
expected the applet to only receive %s (an IPv6 address), instead it
received the following address: '''


DNSv6LookupBadPlural = '''The DNS resolver you are using deliberately
manipulates results.  This can prove problematic, as you will be
unable to contact an IPv6-only site: the DNS resolver is giving
incorrect results for a system which has only an IPv6 address.  We
expected the applet to only receive %s (an IPv6 address), instead it
received the following addresses: '''

DNSGoogleWhitelist = '''Your DNS resolver is on 
<a href="http://www.google.com/intl/en/ipv6/" target="_blank">Google's IPv6
"whitelist"</a>, which means that Google enables IPv6 access to their
services for you.  '''

DNSGoogleNoWhitelist = '''Your DNS resolver is not on 
<a href="http://www.google.com/intl/en/ipv6/" target="_blank">Google's IPv6
"whitelist"</a>, which means that Google does not enable IPv6 access to
their services for you. '''

DNSv6LookupBadWarning = 'Your DNS resolver manipulates results for IPv6 addresses'

ipv6Connectivity = '''Your host was able to contact our IPv6 
test server successfully.  The requests originated from %s. '''

ipv66to4 = '''  This IP address suggests you are using 6to4 for IPv6
connectivity. '''

ipv6teredo = '''  This IP address suggests you are using Teredo for
IPv6 connectivity. '''

ipv6NoConnectivity = '''Your host was not able to contact a separate
server using IPv6, but was able to contact the same server using
IPv4. '''

ipv6NotExecuted = '''Your host was not able to contact our IPv6
server for testing. '''

ipv6Latency = '''It takes %s ms for your computer to fetch a
response from our test server using IPv6, while it takes %s ms for the
same host to fetch a response using IPv4 from the same server. '''


v6BrowserProblem = '''Your web browser has a problem accessing IPv6 sites'''

v6BrowserPresent = '''Your browser successfully fetched a test image from our IPv6 server. '''
v6Manipulated = '''Some process (either your DNS server on an
in-path HTTP proxy) caused the replacement of the test image sent from
our server!'''
v6BrowserAbsent = '''Your browser was unable to fetch a test image
from an IPv6-only server. IPv4 performance to our IPv4-only server did
not differ substantially from our IPv4/IPv6 dual-stacked one. '''
v6BrowserSlow = ''' Unfortunately, this is substantially slower than
IPv4: it took %.1f seconds longer to fetch the image over IPv6
compared to IPv4. '''

v6BrowserMixedSlow = '''Your browser has problems accessing sites
supporting both IPv4 and IPv6.  It took %.1f seconds longer to fetch
the image from the dual-stacked site than from an IPv4-only one. '''

v6BrowserDSProblem = '''Your browser cannot access sites
supporting both IPv4 and IPv6. '''

v6BrowserV6Pref = ''' Your browser prefers IPv6 over IPv4. '''
v6BrowserV4Pref = ''' Your browser prefers IPv4 over IPv6. '''

hostFutureV6 = '''Your host supports IPv6'''
hostFutureNoV6 = '''Your host does not appear to support IPv6'''
hostFutureV6NotChecked = '''Netalyzr was unable to check your network interfaces for IPv6 support'''
hostFutureNoV6Warning = '''Your host does not appear to support IPv6'''

# ednsStatus=none
EDNSNone = \
'''Your DNS resolver does not use EDNS. '''

# ednsStatus=EDNS
EDNSUsed = \
'''Your DNS resolver uses EDNS (Extended DNS). '''

# ednsStatus=DNSSEC
DNSSEC = \
'''Your DNS resolver requests DNSSEC records. '''

# ednsMTU != '0'
EDNSMTU = \
'''Your DNS resolver advertises the ability to accept DNS packets of up to %s bytes. '''


# ednsLarge = "True"
EDNSLargeTrue = '''Your DNS resolver can successfully receive a
large (>1500 byte) DNS response. '''

# ednsLarge = "False"
EDNSLargeFalse = '''Your DNS resolver is unable to receive a large
(>1500 byte) DNS response successfully, even though it advertises
itself as EDNS-enabled. '''

EDNSMediumTrue = '''Your DNS resolver can successfully receive a
smaller (~1400 byte) DNS response. '''

EDNSMediumFalse = '''Your DNS resolver is unable to receive a medium
sized (~1400 byte) DNS response successfully, even though it
advertises itself as EDNS-enabled. '''

ExternalDNSProxy = '''<p>Your host, NAT, or firewall acts as a DNS server
or proxy.  Requests sent to this server are eventually processed by
%s.</p> <p>This is probably a bug in your NAT's firmware, and represents a
minor security vulnerability.</p>'''

ExternalDNSRefused = '''Your host refuses external
DNS requests. '''

ExternalDNSSilent = '''Your host ignores external DNS
requests. '''

ExternalDNSProxyWarning = '''Your IP address acts as a DNS server '''


DNSActualMTU = '''Your DNS resolver accepts DNS responses of up to %i bytes. '''

DNSActualMTULarge = '''Your DNS resolver can successfully accept large responses. '''

BrowserParameters = \
'''The following parameters are sent by your web browser to all web
sites you visit: '''

# Yeup, yet another Firefox version
FirefoxVersion = '3.0.11'

# Firefox 2 still has security updates maintained
Firefox2Version = '2.0.0.20'

BrowserOldWarning = \
'''Your web browser may need updating'''

BrowserOld = \
'''The User Agent string presented by your web browser suggests that
it is out of date.  You should update your web browser to the latest
version available. '''

BrowserJavaOS = 'Java identifies your operating system as %s. '

FilterTestFailed = \
'''None of the test files were transmitted successfully. '''

FiletypeFiltered = \
'''Files of type %s are blocked by the network. '''

FiletypeModified = \
'''Files of type %s are modified by the network. '''

FiletypeUnchanged = \
'''Files of type %s remain unmodified by the network. '''

FilterWarning = \
'''Content filters or compression proxies appear to be present in the network'''

FiletypeCompressed = \
'''<BR>This appears due to a proxy which is performing compression, as
a Content-Encoding: %s header was added. '''

FilterVirusWarning = \
'''Virus filtering appears to be present on your host or network'''

NoFiltering = \
'''We did not detect file-content filtering. '''

VirusFiltering = \
'''A test "virus" (the benign EICAR test file that antivirus vendors
recognize as a test) was blocked or modified in transit. '''

NoVirusFiltering = \
'''A test "virus" (the benign EICAR test file that antivirus vendors
recognize as a test) was not modified in transit. '''

ClockDriftNone = "Your computer's clock agrees with our server's clock."
ClockDrift = "Your computer's clock is %(amount)9.0f seconds %(off)s."
ClockDriftWarning = "Your computer's clock is %(how)s %(off)s"
ClockDriftSlightly = "slightly"
ClockDriftSubstantially = "substantially"
ClockDriftFast = "fast"
ClockDriftSlow = "slow"

UploadAddlContent = 'The following additional content was uploaded by the applet: '
UploadNoAddlContent = 'The applet uploaded no additional data. '

# Contact form layout & text
# ----------------------------------------------------------------------
#
# The contact form. Careful, lots of parameters.  When changing fields
# here, you need to update the code in the SessionResult class
# too. --cpk
#
ContactForm = \
'''<p>%(headline)s</p>

<form action="%(action)s" method="post" enctype="multipart/form-data">
<p>How is your machine connected to the network?<br>
<input type="radio" name="type" value="wifi" %(type_wifi_check)s>Wireless</input>
<input type="radio" name="type" value="wired" %(type_wired_check)s>Wired</input><br>
</p>

<p>Where are you right now?<br>
<input type="radio" name="loc" value="home" %(loc_home_check)s>At home</input><br>
<input type="radio" name="loc" value="work" %(loc_work_check)s>At work</input><br>
<input type="radio" name="loc" value="pub" %(loc_pub_check)s>In a public setting (wifi hotspot, Internet cafe, etc.)</input><br>
<input type="radio" name="loc" value="other" %(loc_other_check)s>Other (please describe in comments below)</input>
</p>

<p>Feel free to leave additional comments below.<br>
<textarea NAME="comments" rows="5" cols="60">
%(comments)s
</textarea>
</p>

<p>Your email address: <input type="text" NAME="email" value="%(email)s"></input>
<input type=submit value="%(submit)s"></input></p>
</form>'''

ContactFormFirstHeadline = '''Please take a moment to tell us about
your network. All fields are optional.  If you would like to contact
us with questions about your results, please
<a href="mailto:netalyzr-help@icsi.berkeley.edu?subject=[Netalyzr %s]">contact us</a>
with your session ID, or get in touch on the
<a href="http://mailman.icsi.berkeley.edu/mailman/listinfo/netalyzr">mailing list</a>. '''

ContactFormRepeatHeadline = \
'''Thank you for your feedback. You can still alter the information below. '''

# If email address wasprovided by user, the result says contains " by
# <email address>":
ContactFormRestoreDataBy = ' by '
ContactFormRestoreData = \
'''The following feedback was reported for this session%s. '''

ContactFormRestoreNoData = \
'''No feedback was reported for this session. '''

ContactFormNetType = \
'''The client used a %s network connection. '''

ContactFormLoc = \
'''The session was conducted at %s. '''

ContactFormComment = \
'''The user commented: '''

ContactFormSubmitLabel = "Send Feedback"
ContactFormRepeatSubmitLabel = "Submit Additional Information"

# Wired network, such as Ethernet
ContactFormWired = 'wired'

# Wireless network connectivity, WLAN
ContactFormWireless = 'wireless'

# Location: at home
ContactFormHome = 'home'

# Location: at work/office
ContactFormWork = 'work'

ContactFormPublic = 'a public location'
ContactFormLocDescr = 'a location described below'
ContactFormNoLoc = 'an unspecified location'
