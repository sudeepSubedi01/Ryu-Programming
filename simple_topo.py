from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI

class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.0.1') # Web Server (Victim)
        h2 = self.addHost('h2', ip='10.0.0.2') # Normal Client
        h3 = self.addHost('h3', ip='10.0.0.3') # Attacker
        
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

if __name__ == '__main__':
    topo = MyTopo()
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSSwitch)
    net.start()     # Createa and Starts Network
    CLI(net)
    net.stop()