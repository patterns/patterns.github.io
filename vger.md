# Gemini, the Middle Child Between Mercury and Apollo
Here is the short list of articles that helped us configure:

[=> Gemini server configuration on OpenBSD](https://0x19.org/posts/2022-01-02.php)
[=> Vger Gemini server](https://tildegit.org/solene/vger/)
[=> OpenBSD and Let's Encrypt](https://www.openbsdhandbook.com/services/webserver/ssl/)


## § TLS
Just follow the steps for the acme-client. Don't install Certbot. It has dependencies and adds endless packages required as a Python application. (Probably a good candidate for being Snap'd or Dockerized)

We use the FQDN (gemini.tfx.tw) when the examples show the IP address or the root domain name. There are trade offs; since we do not have a static IP we will have to deal with updating DNS records as necessary.

For Cloudflare DNS, we want to stop the proxy option on the A and CNAME records because it expects HTTPS.

We may need to add the cron job to renew the certificate in 90 days. Skipped it for now.


          -----
## * Notes, Lessons, Monologue
* Is Gemini good? The protocol has many critics and the FAQ addresses the most pressing concerns. There it's stated that the purpose is not to replace web pages, but rather to fill the space between Mercury/Gopher and Apollo/Web. Reading these limitations, it reminded me of the early days of Twitter when messages were only 128 characters, and adopters tried to explain its immediacy.
* Why abandon CSS styling? The FAQ answer promotes the responsiblity of presentation to the client. It states matter of factly that each user has their own preference, and basically how ridiculous the demand can be on the implementation to achieve a consistent user experience. To some, this may seem like a relinquishing of the problem. However in my mind, this is great in its admission of real world stresses. One of the claims that surface weekly now that makes me chuckle is that the web browser promise was to develop once and have your app run across platforms. How naive we were. 

_________________________________________
2022 興怡 | Always wrong, sometimes lucky

