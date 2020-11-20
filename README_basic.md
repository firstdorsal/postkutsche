# Postkutsche
<img draggable="none" src="https://git.y.gy/firstdorsal/postkutsche/-/raw/master/logo.jpg" style="float:left; margin-right:10px;" height="100"> 

## A module that combines **PowerDns** and **Mailcow** to create a mail domain with all required entries on both services in a single command.

[![npm](https://ico.y.gy/npm/dm/postkutsche?style=flat-square&logo=npm)](https://www.npmjs.com/package/postkutsche)
[![NPM](https://ico.y.gy/npm/l/postkutsche?style=flat-square&color=brightgreen)](https://www.npmjs.com/package/postkutsche)
[![Snyk Vulnerabilities for npm package](https://ico.y.gy/snyk/vulnerabilities/npm/postkutsche?style=flat-square&logo=snyk)](https://snyk.io/test/npm/postkutsche)
[![Website](https://ico.y.gy/website?down_color=red&down_message=offline&label=documentation&up_color=success&up_message=online&url=https%3A%2F%2Fdoc.y.gy%2Fpostkutsche&style=flat-square&logo=)](https://doc.y.gy/postkutsche/)
[![Website](https://ico.y.gy/website?down_color=red&down_message=offline&label=repository&up_color=success&up_message=online&url=https%3A%2F%2Fgit.y.gy%2Ffirstdorsal%2Fpostkutsche&style=flat-square&logo=gitlab)](https://git.y.gy/firstdorsal/postkutsche/)


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
