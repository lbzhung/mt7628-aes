# Mediatek AES Crypto Engine

New and improved AES Crypto Engine. Written from scratch to enable full features and performance.

Attemping to queue request directly into the hardware engine ring descriptors to maximize performance. Work in Progress at the moment.

This AES Engine is available in the Mediatek MT7628 and MT7688 SoC

Possibly the RT6856 is using the engine. The Datasheet specifies AES Engine like the MT7628.
Media releases about the Ralink RT6856 state it as IPSec accelerator.

For now (since its target is MT76x8) only Little Endian supported.
