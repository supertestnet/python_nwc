# Python NWC
A python3 library for working with Nostr Wallet Connect

# Dependencies
The library has three dependencies:
```bash
pip3 install websocket-client secp256k1 pycryptodome==3.10.1
```

The websocket-client library manages a connection to a nostr relay and sends/receives events

The secp256k1 library generates cryptographic keys and signs event messages

The pycryptodome library encrypts and decrypts nostr dms

I also use the some imports that should not need to be installed via pip3 because they are already included by default in python3:

```
import json
import base64
import time
import math
import hashlib
import threading
```

# Use it like this

```python3
nwc_info = processNWCstring( "nostr+walletconnect://2fbe00e6698e717593febba15a68c37de13869b5c304cb8448fa3c541f8620c4?relay=wss://example.relay.com&secret=370d89b58cb4c38fccd4bba520fbbd9397f3682547b66b23a9a6888fef021038&lud16=example@lightning.com" )
```

# Make an invoice for 100 sats with description "hello world!"

```python3
amnt = 100
desc = "hello world!"
invoice_info = makeInvoice( nwc_info, amnt, desc )
```

# Check an invoice's status

```python3
invoice = "lntb2500n1pwxlkl5pp5g8hz28tlf950ps942lu3dknfete8yax2ctywpwjs872x9kngvvuqdqage5hyum5yp6x2um5yp5kuan0d93k2cqzyskdc5s2ltgm9kklz42x3e4tggdd9lcep2s9t2yk54gnfxg48wxushayrt52zjmua43gdnxmuc5s0c8g29ja9vnxs6x3kxgsha07htcacpmdyl64"
invoice_info = checkInvoice( nwc_info, invoice )
```

# Check a payment's status

This method will return false if a payment did not succeed yet. If the payment did succeed, it will return the invoice preimage.

```python3
invoice = "lntb2500n1pwxlkl5pp5g8hz28tlf950ps942lu3dknfete8yax2ctywpwjs872x9kngvvuqdqage5hyum5yp6x2um5yp5kuan0d93k2cqzyskdc5s2ltgm9kklz42x3e4tggdd9lcep2s9t2yk54gnfxg48wxushayrt52zjmua43gdnxmuc5s0c8g29ja9vnxs6x3kxgsha07htcacpmdyl64"
invoice_info = didPaymentSucceed( nwc_info, invoice )
```

# Pay an invoice

Originally my javascript library, of which this is a port, had a method called payInvoice() instead of tryToPayInvoice(). After paying the invoice, it would return the invoice's preimage. I modified its name because (1) lightning payments do not reliably succeed, so I wanted to indicate that through the method name (2) lightning payments sometimes get stuck for several minutes or hours, and I prefer to avoid letting a method get stuck for a long time. So I renamed payInvoice() to tryToPayInvoice() and made it so it never gets stuck, it just immediately sends the "pay" command to the wallet. But that doesn't mean the invoice will actually get paid, so I recommend following that up by calling the didPaymentSucceed() method to find out if the payment went through or not. In the meantime you can show your user a pending status indicator or similar.

If the invoice you're paying is amountless, add an amount to your payment by modifying the variable `amnt`.

```python3
invoice = "lntb2500n1pwxlkl5pp5g8hz28tlf950ps942lu3dknfete8yax2ctywpwjs872x9kngvvuqdqage5hyum5yp6x2um5yp5kuan0d93k2cqzyskdc5s2ltgm9kklz42x3e4tggdd9lcep2s9t2yk54gnfxg48wxushayrt52zjmua43gdnxmuc5s0c8g29ja9vnxs6x3kxgsha07htcacpmdyl64"
amnt = None
tryToPayInvoice( nwc_info, invoice, amnt )
```
