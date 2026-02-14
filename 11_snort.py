from ryu.base import app_manager
from ryu.lib import hub
import os
import socket
import struct

class SnortManualIntegration(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(SnortManualIntegration, self).__init__(*args, **kwargs)
        self.socket_path = "/tmp/snort_alert"
        
        # Clean up old socket if it exists
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
            
        self.logger.info(f"Creating Manual Socket at {self.socket_path}")
        self.threads.append(hub.spawn(self._listen_to_snort))

    def _listen_to_snort(self):
        # Create a Unix Domain Socket (Datagram)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(self.socket_path)
        
        # Give permissions so Snort (running as sudo) can write to it
        os.chmod(self.socket_path, 0o777)
        
        self.logger.info("Waiting for Snort alerts...")
        
        while True:
            data = sock.recv(65535)
            if data:
                # Snort Alertpkt header is complex, but the message 
                # usually starts after the first few bytes.
                # For now, print that got 'something'
                self.logger.info("!!! ALERT RECEIVED FROM SNORT !!!")
                # Simple extraction of the message part (offset varies by Snort version)
                self.logger.info(f"Raw Data Length: {len(data)} bytes")