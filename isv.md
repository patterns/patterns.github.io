# TLS InsecureSkipVerify

[=> VerifyConnection](https://pkg.go.dev/crypto/tls@master#example-Config-VerifyConnection)
[=> TLS Steps](https://gemini.circumlunar.space/docs/tls-tutorial.gmi)
[=> Solderpunk Demo3](https://tildegit.org/solderpunk/gemini-demo-3)
[=> SSL/TLS](https://security.stackexchange.com/q/20803/5568)

## §1 /Certificates
Let's Encrypt is a tremendous life saver. It eliminated the mystery and wall around certificates. A TLS connection to our capsule becomes:

```
tls.Dial("tcp", url.Host, nil)
```

That's it. Seems too easy? If every server used Let's Encrypt, we would be done. In reality, we only found two other capsules that run on CA certificates. Enter the InsecureSkipVerify toggle. To define alternate verify logic, we enable the toggle with tls.Config, and supply our version in the VerifyConnection hook.

## §2 /VerifyConnection
The Go doc example is the critical part:

```
	// VerifyConnection can be used to replace and customize connection
	// verification. This example shows a VerifyConnection implementation that
	// will be approximately equivalent to what crypto/tls does normally to
	// verify the peer's certificate.

	// Client side configuration.
	_ = &tls.Config{
		// Set InsecureSkipVerify to skip the default validation we are
		// replacing. This will not disable VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
```

Running it against CA certs still resulted in successful TLS connections. At the same time, it still failed the non-CA capsules. Which meant that InsecureSkipVerify can be enabled (true), without automatically opening the port to every connect request. Now we can start, and check for properties on the remote cert.

## §3 /UnknownAuthorityError
Self-signed certs will cause the standard tls.Dial to error with x509.UnknownAuthorityError. We test for the error type and cast it to utilize the certificate:

```
func certFrom(err error) *x509.Certificate {
	switch et := err.(type) {
	case x509.UnknownAuthorityError:
		uae, _ := err.(x509.UnknownAuthorityError)
		return uae.Cert
```

Then within our alternate verify, we take the cert and promote it to a CA root cert in the x509.VerifyOptions. Notice that we use a guard to condition this logic. It is permitted when we configure with the AcceptUAE bit. It is also permitted when we configure with the PromptUAE bit, but the cert must belong to a capsule from the "known_hosts" file (more explanation in next write-up).

```
	if isv.Has(AcceptUAE) || known && isv.Has(PromptUAE) {
		// treat self-signed cert as if root
		cert.IsCA = true
		opts.Roots = x509.NewCertPool()
		opts.Roots.AddCert(cert)
	}
```

## §4 /HostnameError
From Go 1.15 release, the Subject Alternate Name (SAN) is expected and Common Name (CN) becomes legacy. So there can be capsules on CN until their expiration/renewal generates replacement certs. The legacy CN is exposed as x509.HostnameError:

```
	case x509.HostnameError:
		hne, _ := err.(x509.HostnameError)
		if hne.Certificate.Subject.CommonName == hne.Host {
			return hne.Certificate
		}
```

Since it is possible for different name related issues to fall in this category, we use the Host value that caused the error, and compare it to the CommonName in the cert. This will tell us that the CN was the source of the error. By falling through for other errors, the TLS dial will stop the connection (and can be used for further analysis).

Then back in our alternate verify, we take the cert to obtain its CN and include it with the DNSNames; the list for SAN.

```
	if isv.Has(AcceptLCN) {
		// inject SAN
		leaf.DNSNames = append(leaf.DNSNames, cert.Subject.CommonName)
	}
```

Notice the guard statement prevents the legacy CN recovery unless the AcceptLCN bit is enabled by configuration. There is a conspicuous absence of a condition for PromptLCN bit. We just haven't built that yet; in terms of severity, the CN is checked, not bypassed technically so we bought more time to work on it.

## §5 /CertificateInvalidError
The expired cert is the remaining case that we encountered among the capsule tour. Since an expired cert is clearly a bad cert, we left this case for last and reserved configuration to include for recovery, but feel there is no rush. To detect the case, the error type is x509.CertificateInvalidError:

```
	case x509.CertificateInvalidError:
		cie, _ := err.(x509.CertificateInvalidError)
		if cie.Reason == x509.Expired {
			log.Printf("DEBUG Expired cert, %s", cie.Detail)
			return cie.Cert
		}
```

Since we don't make any recovery currently, it will always cause the TLS connection to stop.

---

## * Notes, Lessons, Monologue
* Bitmasks? With masks, we take the approach to combine recovery options and apply them on the second tls.Dial. It wasn't our initial attempt which was to loop the Dial, and only toggle one recovery option each pass; the idea being to only enable the least number of options. In concept it sounds good, but the code was garbage. Maybe we can think of a design that is elegant, but for now we're doing masks.
* VerifyPeerCertificate? We initially experimented with implementing this hook and failed repeatedly. We just don't have enough understanding yet.
* Opinion? I'm a big fan of the toggle InsecureSkipVerify. Let me explain! NOT the use, but more about its design. It recognizes that there is real need to run that flow, whether a team is doing testing or there is a local/controlled network. Making this toggle built-in, accelerates that necessary work, while at the same time makes it explicit that it must be temporary or isolated, and reviewed under a microscope before shipping. I think this kind of language decision is what was meant when Go was charged with reducing stagnation and fear of touching legacy code. 

###### 2022 興怡 | Always wrong, sometimes lucky

