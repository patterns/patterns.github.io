# SSH InsecureIgnoreHostKey
Short list of articles that helped:
[=> SSH Host Key](https://skarlso.github.io/2019/02/17/go-ssh-with-host-key-verification/)
[=> TLS Steps](https://gemini.circumlunar.space/docs/tls-tutorial.gmi)

## §1 /TOFU
Among our tasks was emulating the way SSH negotiates the first connection to the remote. The user prompt to continue was already familiar. This interaction is important because our dialer must keep the known_hosts file to track "trusted" capsules. The other subtle point is the reason behind this act of trust -- self-signed certificate. Meaning, capsules on self-signed certificates are assumed to be a fast path to launching Gemini content, and common place. To sum up:

* keep known_hosts file 
* prompt user to confirm first visit
* identify self-signed certificates

## §2 /Known_capsules
To begin the recovery flow, we use the "prompt" flag on self-signed certificates. The other flag values are AcceptSSC and SSCReject which mean continue and halt (respectively):

```
func knownCapsules(ctx context.Context, capsule string, cert *x509.Certificate, isv Mask) bool {
	if !isv.Has(PromptSSC) {
		return false
	}

```

We made this flag configurable (via the -json commandline argument), and assigned in the safe defaults as "prompt" (gmi.PromptSSC). 

Then the "trick" is to invoke HostKeyCallback from the ssh/knownhosts package: 

```
import kh "golang.org/x/crypto/ssh/knownhosts"
...
func searchKnown(cert *x509.Certificate, capsule string, kcp string) error {
	sshpk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		log.Printf("DEBUG crt to ssh key failed, %v", err)
		return err
	}
	abs, err := filepath.Abs(kcp)
	if err != nil {
		log.Printf("DEBUG known_capsules path, %v", err)
		return err
	}
	hostKeyCallback, err := kh.New(abs)
	if err != nil {
		log.Printf("DEBUG callback not created, %v", err)
		return err
	}
	addr, err := net.ResolveTCPAddr("tcp", capsule)
	if err != nil {
		log.Printf("DEBUG resolve, %v", err)
		return err
	}
	err = hostKeyCallback(capsule, addr, sshpk)
	if err != nil {
		log.Printf("DEBUG known error, %v", err)
	}
```

Also, we use the filename "known_capsules" to emphasize that the remotes are capsules that are tracked, instead of SSH hosts.

## §3 /User Prompt
For the time being, we have a placeholder. The log output shows the step/event where it is appropriate to make the UI to prompt the user. Currently, it acts as if the choice is 'Y' and continues. It's worth noting because it is a todo, and it maps out the continue flow. For continue flow, the new remote needs a) its public key produced, and b) to be appended to the known_hosts file:

```
	sshpk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("Capsule prompt failed new key, %w", err)
	}
	line := kh.Line([]string{capsule}, sshpk)
	file, err := os.OpenFile(abs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 644)
	if err != nil {
		return fmt.Errorf("Capsule prompt failed file, %w", err)
	}
	defer file.Close()
	_, err = file.WriteString(line)
	if err != nil {
		return fmt.Errorf("Capsule prompt failed append, %w", err)
	}
	file.WriteString("\n")
```


## §4 /Self-signed Cert
Sounds weird, but the TLS dial has to fail THEN we have an error (more in notes below). This error can be cast into different types. x509.UnknownAuthorityError occurs for self-signed certificates because the CA is not recognized.

Snippet of code that identifies self-signed certificates:

```
func certFrom(err error) *x509.Certificate {
	switch et := err.(type) {
	case x509.UnknownAuthorityError:
		uae, _ := err.(x509.UnknownAuthorityError)
		return uae.Cert
```


---

## * Notes, Lessons, Monologue
* When? During prototype/poc, when iterating inside controlled networks; when you want to concentrate on the functional requirements. The part I really like is the naming clearly identifies InsecureIgnoreHostKey as dangerous. So any code review should easily flag it when found in commits.

* Self-signed certs? It can be argued whether self-signed certificates are too much risk. May be historical, and as time progresses it will change. Let's Encrypt definitely changed things for the better. I was able to obtain a certificate with their CA for free. You have to own a domain name, and be able to configure httpd to respond to the ACME requests. So in theory, all web servers can stop hanging on to self-signed certificates.

* Why waste TLS dial for the error type? I know it seems wasteful. Consider this. The best flow is the standard TLS dial with all the checks in Verify. So making the initial TLS dial is actually our ideal, and the "recovery" flow is to accomodate (Gemini) self-signed certs.

---

2022 興怡 | Always wrong, sometimes lucky

