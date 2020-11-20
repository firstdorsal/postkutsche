[![npm](https://ico.y.gy/npm/dm/postkutsche?style=flat-square&logo=npm)](https://www.npmjs.com/package/postkutsche)
[![NPM](https://ico.y.gy/npm/l/postkutsche?style=flat-square)](https://www.npmjs.com/package/postkutsche)
[![Snyk Vulnerabilities for npm package](https://ico.y.gy/snyk/vulnerabilities/npm/postkutsche?style=flat-square&logo=snyk)](https://snyk.io/test/npm/postkutsche)
[![Website](https://ico.y.gy/website?down_color=red&down_message=offline&label=documentation&up_color=success&up_message=online&url=https%3A%2F%2Fdoc.y.gy%2Fpostkutsche&style=flat-square)](https://doc.y.gy/postkutsche/)
[![Website](https://ico.y.gy/website?down_color=red&down_message=offline&label=repository&up_color=success&up_message=online&url=https%3A%2F%2Fgit.y.gy%2Ffirstdorsal%2Fpostkutsche&style=flat-square&logo=gitlab)](https://git.y.gy/firstdorsal/postkutsche/)

# Description
A module that combines **PowerDns** and **Mailcow** to create a mail domain with all required entries on both services in a single command.

# Install
```
yarn add postkutsche
```
or
```
npm i postkutsche
```
# Basic use
```js
(async () => {
    //import the process.env variables from the .env file in which you should store them
    //you can install dotenv with `npm i dotenv --save-dev` or `yarn add dotenv --dev`
    require('dotenv').config();

    //import the Postkutsche class
    const {
        Postkutsche
    } = require("./index.js");

    //create a new instance of Postkutsche providing it with the necessary api keys
    const pk = new Postkutsche({
        mailcow: {
            url: process.env.MAILCOW_API_URL,
            apikey: process.env.MAILCOW_API_KEY
        },
        powerdns: {
            url: process.env.PDNS_API_URL,
            apikey: process.env.PDNS_API_KEY
        }
    });

    const info={
        nameserver: ['ns1.domain.tld', 'ns2.domain.tld', 'ns3.domain.tld'],
        hostmasterEmail: 'hostmaster@domain.tld',
        dmarcMail: 'postmaster@domain.tld', 
        mailDomain: 'domain.tld',
        mailServerHostname: 'mail.domain.tld',
        defaultMailbox: {
            local_part: `max.mustermensch`,
            name: `Max Mustermensch`
        },
        //NEEDED FOR MAILSERVER DOMAIN SETUP
        mailServerIp: '2a00:1450:4016:801::2003', //Your IPv6 address WITHOUT brackets([]) 
        mailServerLegacyIp: '127.0.0.1',//Your IPv4 address
        addLetsEncryptCAA: true,
        caaReportMail: 'caa.report@domain.tld' //can be set if you want to get reports on malicious cert issues
    }

    //use a function from the Postkutsche class
    //adds the mail records for a domain and creates the domain on mailcow
    await pk.addMailDomain(info);
})();
```


# Need help or missing a feature?
Feel free to contact me via [xl9jthv_7bvgakv9o9wg0jabn2ylm91xxrzzgt0e@y.gy](mailto:xl9jthv_7bvgakv9o9wg0jabn2ylm91xxrzzgt0e@y.gy) in english or german

## Links
[NPM](https://www.npmjs.com/package/postkutsche)

[Documentation](https://doc.y.gy/postkutsche/)

[Code](https://git.y.gy/firstdorsal/postkutsche)

### powerdns-api
[NPM](https://www.npmjs.com/package/@firstdorsal/powerdns-api)

[Documentation](https://doc.y.gy/powerdns-api/)

[Code](https://git.y.gy/firstdorsal/powerdns-api)

### mailcow-api
[NPM](https://www.npmjs.com/package/mailcow-api)

[Documentation](https://doc.y.gy/mailcow-api/)

[Code](https://git.y.gy/firstdorsal/mailcow-api)
## Modules

<dl>
<dt><a href="#module_postkutsche">postkutsche</a></dt>
<dd></dd>
</dl>

## Typedefs

<dl>
<dt><a href="#ApiInfo">ApiInfo</a> : <code>object</code></dt>
<dd></dd>
<dt><a href="#Info">Info</a> : <code>object</code></dt>
<dd></dd>
</dl>

<a name="module_postkutsche"></a>

## postkutsche

* [postkutsche](#module_postkutsche)
    * [.Postkutsche](#module_postkutsche.Postkutsche)
        * [new module.exports.Postkutsche(info)](#new_module_postkutsche.Postkutsche_new)
        * [.getTLSA(info)](#module_postkutsche.Postkutsche+getTLSA) ⇒ <code>Array</code>
        * [.genMailDomainRecords(info)](#module_postkutsche.Postkutsche+genMailDomainRecords) ⇒ <code>Array</code>
        * [.addMailDomain(info, [log])](#module_postkutsche.Postkutsche+addMailDomain) ⇒ <code>Boolean</code>
        * [.addMailServerDnsRecords(info, [log])](#module_postkutsche.Postkutsche+addMailServerDnsRecords) ⇒ <code>Boolean</code>
        * [.openpgpHash(localPart)](#module_postkutsche.Postkutsche+openpgpHash)
        * [.openpgpRecord(localPart, publicKeyB64)](#module_postkutsche.Postkutsche+openpgpRecord) ⇒ <code>OpenpgpRecord</code>
        * [.setOpenpgpRecord(localPart, domain, publicKeyB64)](#module_postkutsche.Postkutsche+setOpenpgpRecord)
        * [.cleanupAddMailServer(info)](#module_postkutsche.Postkutsche+cleanupAddMailServer)
        * [.cleanupAddMailDomain(info)](#module_postkutsche.Postkutsche+cleanupAddMailDomain)

<a name="module_postkutsche.Postkutsche"></a>

### postkutsche.Postkutsche
Class representing the Postkutsche client

**Kind**: static class of [<code>postkutsche</code>](#module_postkutsche)  

* [.Postkutsche](#module_postkutsche.Postkutsche)
    * [new module.exports.Postkutsche(info)](#new_module_postkutsche.Postkutsche_new)
    * [.getTLSA(info)](#module_postkutsche.Postkutsche+getTLSA) ⇒ <code>Array</code>
    * [.genMailDomainRecords(info)](#module_postkutsche.Postkutsche+genMailDomainRecords) ⇒ <code>Array</code>
    * [.addMailDomain(info, [log])](#module_postkutsche.Postkutsche+addMailDomain) ⇒ <code>Boolean</code>
    * [.addMailServerDnsRecords(info, [log])](#module_postkutsche.Postkutsche+addMailServerDnsRecords) ⇒ <code>Boolean</code>
    * [.openpgpHash(localPart)](#module_postkutsche.Postkutsche+openpgpHash)
    * [.openpgpRecord(localPart, publicKeyB64)](#module_postkutsche.Postkutsche+openpgpRecord) ⇒ <code>OpenpgpRecord</code>
    * [.setOpenpgpRecord(localPart, domain, publicKeyB64)](#module_postkutsche.Postkutsche+setOpenpgpRecord)
    * [.cleanupAddMailServer(info)](#module_postkutsche.Postkutsche+cleanupAddMailServer)
    * [.cleanupAddMailDomain(info)](#module_postkutsche.Postkutsche+cleanupAddMailDomain)

<a name="new_module_postkutsche.Postkutsche_new"></a>

#### new module.exports.Postkutsche(info)
Create a postkutsche client.


| Param | Type | Description |
| --- | --- | --- |
| info | [<code>ApiInfo</code>](#ApiInfo) | The provided [ApiInfo](https://doc.y.gy/postkutsche/global.html#ApiInfo) object |

**Example**  
```js
(async () => {
    //import the process.env variables from the .env file in which you should store them
    //you can install dotenv with `npm i dotenv --save-dev` or `yarn add dotenv --dev`
    require('dotenv').config();

    //import the Postkutsche class
    const {
        Postkutsche
    } = require("./index.js");

    //create a new instance of Postkutsche providing it with the necessary api keys
    const pk = new Postkutsche({
        mailcow: {
            url: process.env.MAILCOW_API_URL,
            apikey: process.env.MAILCOW_API_KEY
        },
        powerdns: {
            url: process.env.PDNS_API_URL,
            apikey: process.env.PDNS_API_KEY
        }
    });

    const info={
        nameserver: ['ns1.domain.tld', 'ns2.domain.tld', 'ns3.domain.tld'],
        hostmasterEmail: 'hostmaster@domain.tld',
        dmarcMail: 'postmaster@domain.tld', 
        mailDomain: 'domain.tld',
        mailServerHostname: 'mail.domain.tld',
        defaultMailbox: {
            local_part: `max.mustermensch`,
            name: `Max Mustermensch`
        },
        //NEEDED FOR MAILSERVER DOMAIN SETUP
        mailServerIp: '2a00:1450:4016:801::2003', //Your IPv6 address WITHOUT brackets([]) 
        mailServerLegacyIp: '127.0.0.1',//Your IPv4 address
        addLetsEncryptCAA: true,
        caaReportMail: 'caa.report@domain.tld' //can be set if you want to get reports on malicious cert issues
    }

    //use a function from the Postkutsche class
    //adds the mail records for a domain and creates the domain on mailcow
    await pk.addMailDomain(info);
})();
```
<a name="module_postkutsche.Postkutsche+getTLSA"></a>

#### postkutsche.getTLSA(info) ⇒ <code>Array</code>
**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  
**Returns**: <code>Array</code> - with tlsa records ready to be inserted into powerdns  

| Param | Type | Description |
| --- | --- | --- |
| info | [<code>Info</code>](#Info) | [Info](https://doc.y.gy/postkutsche/global.html#Info) object with the necessary information to generate the tlsa records |

**Example**  
```js
await pk.getTLSA({
            mailServerHostname: 'mail.domain.tld',
            mailServerIp: '2a00:1450:4016:801::2003',
            mailServerLegacyIp: '127.0.0.1'
        });
```
<a name="module_postkutsche.Postkutsche+genMailDomainRecords"></a>

#### postkutsche.genMailDomainRecords(info) ⇒ <code>Array</code>
**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  
**Returns**: <code>Array</code> - with domain relevant mail records  

| Param | Type | Description |
| --- | --- | --- |
| info | [<code>Info</code>](#Info) | [Info](https://doc.y.gy/postkutsche/global.html#Info) object with the necessary information to generate the domain mail records |

**Example**  
```js
pk.genMailDomainRecords({
            mailServerHostname: 'mail.domain.tld',
            mailDomain: 'domain.tld',
            dmarcMail: 'dmarc@domain.tld'
        });
```
<a name="module_postkutsche.Postkutsche+addMailDomain"></a>

#### postkutsche.addMailDomain(info, [log]) ⇒ <code>Boolean</code>
This will add:
 - Mailcow: 
     - Domain (if not present)
     - Mailbox (if not present)
     - DKIM Key (if not present)
     - Alias: catchall (catchall will relay everything @yourdomain.tld to your Mailbox) (if not present)
 - PowerDns: 
     - Domain (if not present)
     - Mail records for the domain (won't touch other records but will overwrite present matching records)
     - DNSSEC (if domain wasn't present)
     - Create record on mailServerDomain(if not the same as mailDomain) to allow dmarc mails to sent to this domain

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  
**Returns**: <code>Boolean</code> - true on success  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| info | [<code>Info</code>](#Info) |  | [Info](https://doc.y.gy/postkutsche/global.html#Info) object with the necessary information to create a mail domain on mailcow and the necessary records on powerdns |
| [log] | <code>Boolean</code> | <code>true</code> | you can disable logging by setting this to false |

**Example**  
```js
await pk.addMailDomain({
            nameserver: ['ns1.domain.tld', 'ns2.domain.tld', 'ns3.domain.tld'],
            hostmasterEmail: 'hostmaster@domain.tld',
            dmarcMail: 'postmaster@domain.tld', 
            mailDomain: 'domain.tld',
            mailServerHostname: 'mail.domain.tld',
            defaultMailbox: {
                local_part: `max.mustermensch`,
                name: `Max Mustermensch`,
                password:`set some good password here` //can be omitted
            }
        });
```
<a name="module_postkutsche.Postkutsche+addMailServerDnsRecords"></a>

#### postkutsche.addMailServerDnsRecords(info, [log]) ⇒ <code>Boolean</code>
This will add:
 - PowerDns: 
     - Domain for the mailserver hostname (if not present)
     - DNSSEC (will replace old dnssec if present)
     - TLSA records for the domain (for the creation of the tlsa records you need to have openssl installed. you can specify the path, if it can't be found globally as 'openssl')
     - Records for the mailserver

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  
**Returns**: <code>Boolean</code> - true on success  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| info | [<code>Info</code>](#Info) |  | [Info](https://doc.y.gy/postkutsche/global.html#Info) object with the necessary information to create the relevant records for the mailserver |
| [log] | <code>Boolean</code> | <code>true</code> | you can disable logging by setting this to false |

**Example**  
```js
await pk.addMailServerDnsRecords({
            nameserver: ['ns1.domain.tld', 'ns2.domain.tld', 'ns3.domain.tld'],
            hostmasterEmail: 'hostmaster@domain.tld',
            mailServerHostname: 'mail.domain.tld',
            mailServerIp: '2a00:1450:4016:801::2003', //Your IPv6 address WITHOUT brackets([]) 
            mailServerLegacyIp: '127.0.0.1',//Your IPv4 address
            addLetsEncryptCAA: true,
            caaReportMail: 'caa.report@domain.tld' //can be set if you want to get reports on malicious cert issues
    });
```
<a name="module_postkutsche.Postkutsche+openpgpHash"></a>

#### postkutsche.openpgpHash(localPart)
Creates the front part of the openpgp dns record

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  

| Param | Type | Description |
| --- | --- | --- |
| localPart | <code>String</code> | local part of your email address (the part before the @ not including the @) |

**Example**  
```js
console.log(pk.openpgpHash('max.mustermensch'));
```
<a name="module_postkutsche.Postkutsche+openpgpRecord"></a>

#### postkutsche.openpgpRecord(localPart, publicKeyB64) ⇒ <code>OpenpgpRecord</code>
Creates an openpgp dns record

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  

| Param | Type | Description |
| --- | --- | --- |
| localPart | <code>String</code> | local part of your email address (the part before the @ not including the @) |
| publicKeyB64 | <code>String</code> | your publickey in base64 (it should be correct if it includes -----BEGIN PGP PUBLICKEY BLOCK-----) or only contains these characters: A-Z a-z 0-9 + / |

**Example**  
```js
console.log(pk.openpgpRecord('max.mustermensch','-----BEGIN PGP (...)'));
```
<a name="module_postkutsche.Postkutsche+setOpenpgpRecord"></a>

#### postkutsche.setOpenpgpRecord(localPart, domain, publicKeyB64)
Sets an openpgp record on your powerdns server
Will overwrite key with the same local part

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  

| Param | Type | Description |
| --- | --- | --- |
| localPart | <code>String</code> | local part of your email address (the part before the @ not including the @) |
| domain | <code>String</code> | the domain you want to add the key to |
| publicKeyB64 | <code>String</code> | your publickey in base64 (it should be correct if it includes -----BEGIN PGP PUBLICKEY BLOCK-----) or only contains these characters: A-Z a-z 0-9 + / |

**Example**  
```js
await pk.setOpenpgpRecord('max.mustermensch','domain.tld','-----BEGIN PGP (...)');
```
<a name="module_postkutsche.Postkutsche+cleanupAddMailServer"></a>

#### postkutsche.cleanupAddMailServer(info)
Will delete the complete mailserver domain from powerdns

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  

| Param | Type | Description |
| --- | --- | --- |
| info | [<code>Info</code>](#Info) | [Info](https://doc.y.gy/postkutsche/global.html#Info) object with the necessary information to delete the mailserver domain |

**Example**  
```js
pk.cleanupAddMailServer({mailServerHostname:'mail.domain.tld'});
```
<a name="module_postkutsche.Postkutsche+cleanupAddMailDomain"></a>

#### postkutsche.cleanupAddMailDomain(info)
Will delete a domain from powerdns and mailcow
THIS WILL DELETE YOUR MAILBOX AND EVERYTHING ELSE CONCERNING THIS DOMAIN

**Kind**: instance method of [<code>Postkutsche</code>](#module_postkutsche.Postkutsche)  

| Param | Type | Description |
| --- | --- | --- |
| info | [<code>Info</code>](#Info) | [Info](https://doc.y.gy/postkutsche/global.html#Info) object with the necessary information to create a mail domain on mailcow and the necessary records on powerdns |

**Example**  
```js
await pk.cleanupAddMailDomain({
             dmarcMail: 'postmaster@domain.tld', 
             mailDomain: 'domain.tld',
             defaultMailbox: {
                 local_part: `max.mustermensch`,
                 name: `Max Mustermensch`
             }
         });
```
<a name="ApiInfo"></a>

## ApiInfo : <code>object</code>
**Kind**: global typedef  
**Properties**

| Name | Type |
| --- | --- |
| mailcow | <code>object</code> | 
| mailcow.url | <code>string</code> | 
| mailcow.apikey | <code>string</code> | 
| powerdns | <code>object</code> | 
| powerdns.url | <code>String</code> | 
| powerdns.apikey | <code>String</code> | 

**Example**  
```js
{
        mailcow: {
            url: process.env.MAILCOW_API_URL,
            apikey: process.env.MAILCOW_API_KEY
        },
        powerdns: {
            url: process.env.PDNS_API_URL,
            apikey: process.env.PDNS_API_KEY
        }
    }
```
<a name="Info"></a>

## Info : <code>object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| nameserver | <code>Array.&lt;string&gt;</code> |  | array of nameservers for your domain, first ns in the list will be used as primary |
| hostmasterEmail | <code>string</code> |  | hostnmaster email address |
| [dmarcMail] | <code>string</code> |  | add mail if you want to get dmarc reports |
| mailDomain | <code>string</code> |  | the domain you may want to add mail for |
| mailServerHostname | <code>String</code> |  | the hostname of the mailserver |
| defaultMailbox | <code>Object</code> |  |  |
| defaultMailbox.local_part | <code>String</code> |  | local part of you mailbox (the part before the @ not including the @) |
| defaultMailbox.name | <code>String</code> |  | the name of mailbox |
| [defaultMailbox.password] | <code>String</code> | <code>RANDOM</code> | will generate a random password for your mailbox if omitted |
| mailServerIp | <code>String</code> |  | IPv6 address of your mailserver |
| mailServerLegacyIp | <code>String</code> |  | IPv4 address of your mailserver |
| [addLetsEncryptCAA] | <code>Boolean</code> |  | enable this option if you are ONLY using letsencrypt certs |
| [caaReportMail] | <code>String</code> |  |  |
| [openssl_path] | <code>String</code> | <code>&#x27;openssl&#x27;</code> | optional alternative path for openssl |

**Example**  
```js
{
        nameserver: ['ns1.domain.tld', 'ns2.domain.tld', 'ns3.domain.tld'],
        hostmasterEmail: 'hostmaster@domain.tld',
        dmarcMail: 'postmaster@domain.tld', 
        mailDomain: 'domain.tld',
        mailServerHostname: 'mail.domain.tld',
        defaultMailbox: {
            local_part: `max.mustermensch`,
            name: `Max Mustermensch`
        },
        //NEEDED FOR MAILSERVER DOMAIN SETUP
        mailServerIp: '2a00:1450:4016:801::2003', //Your IPv6 address WITHOUT brackets([]) 
        mailServerLegacyIp: '127.0.0.1',//Your IPv4 address
        addLetsEncryptCAA: true,
        caaReportMail: 'caa.report@domain.tld' //can be set if you want to get reports on malicious cert issues
    }
```
