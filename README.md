# pcap-proxy
A simple userland TCP proxy application that captures the network flow into a .pcap file

Sometimes you don't have permission to tcpdump/wireshark; if you've control over the client side, this tool is still a useful alternative to inspect the TCP level communication.

The http proxy expects a standard CONNECT somehost:port HTTP/1.0 kind of connection setup, and supports TLS connections only. It rewraps the communication and saves a cleartext dump.
If the application to be monitored does not respect the standard HTTPS_PROXY environment variable, you can setup a transparent TCP proxy e.g. by using my another tool:

https://github.com/irsl/tcp-http-proxy

![H2/ALPN/TLS](https://github.com/irsl/pcap-proxy/raw/master/src/illustration.png "H2/ALPN/TLS")
