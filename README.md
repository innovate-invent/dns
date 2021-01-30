# dns

NodeJS dns library compatible for browsers. Why would you want to make DNS requests from a browser? DNS has numerous
functions other than mapping domain names to IP addresses. SRV and TXT records offer the ability to do service discovery
and distribute information such as public keys.

**This library uses AbortController, which is not compatible with Internet Explorer.** A polyfill may be available,
but is not included.

See the [NodeJS dns documentation](https://nodejs.org/api/dns.html) for information on how to use this library.
The [caveats](https://nodejs.org/api/dns.html#dns_implementation_considerations) mentioned in the documentation
regarding `lookup`, `lookupService` and `reverse` do not apply. These functions call system operations not available to
the browser. In this implementation `lookup` simply aliases `resolve`, `lookupService` and `reverse` will throw errors
when called. `hints` and `verbatim` arguments of `lookup` are ignored. The errors are thrown in a way that any proper
error handling that would normally be present while using the NodeJS dns library should also handle these errors.
`setLocalAddress` is a no-op function. `getServers` and `setServers` return/accept a list of strings containing the
hostnames of the 'DNS over HTTPS' providers that the resolver makes requests against.

This library is able to function by using any 'DNS over HTTPS' services. The default resolver is CloudFlare using 
cloudflare-dns.com. Support for any of the providers listed under 'DNS over HTTPS' at 
https://en.wikipedia.org/wiki/Public_recursive_name_server can be added. Currently, only providers CloudFlare,
OpenDNS, and Google are implemented. Contributions are welcome.

`dns.Resolver` is implemented as a wrapper around the Promise based resolvers to support the callback interface. Pass an
instantiated Promise resolver to the constructor to wrap different provider resolvers:

```typescript
import dns from 'dns'
import CFResolver from 'dns/cloudflare'

const resolver = new dns.Resolver(new CFResolver({timeout: 30}));
```

All methods exported by the library use the CloudFlare resolver. Instantiate a resolver imported for the specific
provider submodule to use that provider. `class Resolver` implementations export `lookup` and `lookupService` in
addition to the methods defined in the
[NodeJS dns documentation](https://nodejs.org/api/dns.html).
