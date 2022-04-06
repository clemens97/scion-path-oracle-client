# Path Oracle Client

This repository contains sample applications to test different path selectors for [SCION](https://scion-architecture.net/).
SCION is a modern Internet architecture providing path awareness to its hosts, allowing them to select
the path their packets traverse actively.

To test different path selection strategies for network-bound I/O performing applications, this repository contains:
- a client to communicate with a [Path Oracle](https://github.com/clemens97/scion-path-oracle),
- different path selectors,
- a sender sending randomized data via QUIC (utilizing one of the implemented path selectors)
- a receiver receiving any incoming data (utilizing the reverse path for response packets)