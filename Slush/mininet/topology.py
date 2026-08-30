from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

def build():
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    # Point this at your Ryu controller's IP
    c0 = net.addController('c0', ip='127.0.0.1', port=6653)

    s1 = net.addSwitch('s1')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')   # "attacker"
    h4 = net.addHost('h4', ip='10.0.0.4/24')   # "victim" / server

    for h in (h1, h2, h3, h4):
        net.addLink(h, s1)

    net.build()
    c0.start()
    s1.start([c0])

    print("Network built. h4 (10.0.0.4) is the server target.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build()
