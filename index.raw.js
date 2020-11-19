"use strict";

const exec = require(`util`).promisify(require(`child_process`).exec);
const secondLevelRegex = new RegExp(/[A-Z-a-z0-9]{1,63}\.[A-Z-a-z0-9]{1,63}$/);
const crypto = require('crypto');

//import the clients
const {
    MailcowApiClient
} = require("mailcow-api")
const {
    PowerdnsClient
} = require('@firstdorsal/powerdns-api');

/**
 * @typedef ApiInfo
 * @type {object}
 * @prop {object} mailcow
 * @prop {string} mailcow.url
 * @prop {string} mailcow.apikey
 * @prop {object} powerdns
 * @prop {String} powerdns.url
 * @prop {String} powerdns.apikey
 * @example
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
 *
 */

/**
* @typedef Info
* @type {object}
* @prop {Array.<string>} nameserver array of nameservers for your domain, first ns in the list will be used as primary
* @prop {string} hostmasterEmail hostnmaster email address
* @prop {string} [dmarcMail] add mail if you want to get dmarc reports
* @prop {string} mailDomain the domain you may want to add mail for
* @prop {String} mailServerHostname the hostname of the mailserver
* @prop {Object} defaultMailbox
* @prop {String} defaultMailbox.local_part local part of you mailbox (the part before the @ not including the @)
* @prop {String} defaultMailbox.name the name of mailbox
* @prop {String} [defaultMailbox.password=RANDOM] will generate a random password for your mailbox if omitted
* @prop {String} mailServerIp IPv6 address of your mailserver
* @prop {String} mailServerLegacyIp IPv4 address of your mailserver
* @prop {Boolean=} addLetsEncryptCAA enable this option if you are ONLY using letsencrypt certs
* @prop {String=} caaReportMail
* @prop {String=} [openssl_path='openssl'] optional alternative path for openssl
* @example
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
*
*/

/**
 * @module Postkutsche
 * @class Class representing the Postkutsche client
 * @example
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
 */
module.exports.Postkutsche = class {

    /**
     * Create a postkutsche client.
     * @constructor
     * @param {ApiInfo} info The provided {@link DOC_URL/global.html#ApiInfo ApiInfo} object
     */
    constructor(info) {
        this.mcc = new MailcowApiClient(info.mailcow.url, info.mailcow.apikey);
        this.pdns = new PowerdnsClient(info.powerdns.url, info.powerdns.apikey);
    }

    /**
     * @param {Info} info {@link DOC_URL/global.html#Info Info} object with the necessary information to generate the tlsa records
     * @async
     * @returns {Array} with tlsa records ready to be inserted into powerdns
     * @example
        await pk.getTLSA({
            mailServerHostname: 'mail.domain.tld',
            mailServerIp: '2a00:1450:4016:801::2003',
            mailServerLegacyIp: '127.0.0.1'
        });
     */
    getTLSA = async (info) => {
        if (!info.openssl_path) info.openssl_path = `openssl`;

        const questions = [{
            name: `smtp over starttls`,
            port: 25,
            starttls: {
                type: `smtp`
            }
        }, {
            name: `web over tls`,
            port: 443,
            starttls: false
        }, {
            name: `pop3 over starttls`,
            port: 110,
            starttls: {
                type: `pop3`
            }
        }, {
            name: `imap over starttls`,
            port: 143,
            starttls: {
                type: `imap`
            }
        }, {
            name: `smtps over tls`,
            port: 465,
            starttls: false
        }, {
            name: `submission over starttls`,
            port: 587,
            starttls: {
                type: `smtp`
            }
        }, {
            name: `imaps over tls`,
            port: 993,
            starttls: false
        }, {
            name: `pop3s over tls`,
            port: 995,
            starttls: false
        }, {
            name: `sieve over starttls`,
            port: 4190,
            starttls: {
                type: `sieve`
            }
        }];
        const answers = await Promise.all(questions.map((e) => {
            e.answer = exec(`
        echo | 
        ${info.openssl_path} s_client -servername ${info.mailServerHostname} -connect ${info.mailServerIp?info.mailServerIp:info.mailServerLegacyIp}:${e.port} ${e.starttls?`-starttls `+e.starttls.type:``} 2>/dev/null | 
        openssl x509 -pubkey -noout | 
        openssl pkey -pubin -outform DER | 
        openssl sha256 |
        sed 's/(stdin)= //g'`)
            return e.answer;
        }));
        questions.map((e, i) => {
            delete e.answer;
            const sha256 = answers[i].stdout.replace(`\n`, ``);
            e.answer = {
                sha256
            };
            e.dns = {
                name: `_${e.port}._tcp.${info.mailServerHostname}.`,
                type: `TLSA`,
                content: [`3 1 1 ${sha256}`]
            }
        });
        return questions;
    }

    /**
     * @param {Info} info {@link DOC_URL/global.html#Info Info} object with the necessary information to generate the domain mail records
     * @returns {Array} with domain relevant mail records
     * @example
        pk.genMailDomainRecords({
            mailServerHostname: 'mail.domain.tld',
            mailDomain: 'domain.tld',
            dmarcMail: 'dmarc@domain.tld'
        });
     */
    genMailDomainRecords = (info) => {
        return [{
                name: `${info.mailDomain}.`,
                type: 'MX',
                content: [`10 ${info.mailServerHostname}.`]
            }, {
                name: `autodiscover.${info.mailDomain}.`,
                type: 'CNAME',
                content: [`${info.mailServerHostname}.`]
            }, {
                name: `_autodiscover._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 443 ${info.mailServerHostname}.`]
            }, {
                name: `autoconfig.${info.mailDomain}.`,
                type: 'CNAME',
                content: [`${info.mailServerHostname}.`]
            }, {
                name: `${info.mailDomain}.`,
                type: `TXT`,
                content: [`"v=spf1 MX -all"`]
            }, {
                name: `_dmarc.${info.mailDomain}.`,
                type: `TXT`,
                content: [`"v=DMARC1;p=reject;sp=reject;${info.dmarcMail?"rua=mailto:"+info.dmarcMail+";ruf=mailto:"+info.dmarcMail+";":""}adkim=s;aspf=s;"`]
            }, {
                name: `_imap._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 143 ${info.mailServerHostname}.`]
            },
            {
                name: `_imaps._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 993 ${info.mailServerHostname}.`]
            },
            {
                name: `_pop3._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 110 ${info.mailServerHostname}.`]
            },
            {
                name: `_pop3s._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 995 ${info.mailServerHostname}.`]
            },
            {
                name: `_submission._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 587 ${info.mailServerHostname}.`]
            },
            {
                name: `_smtps._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 465 ${info.mailServerHostname}.`]
            },
            {
                name: `_sieve._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 4190 ${info.mailServerHostname}.`]
            },
            {
                name: `_carddavs._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 443 ${info.mailServerHostname}.`]
            },
            {
                name: `_caldavs._tcp.${info.mailDomain}.`,
                type: 'SRV',
                content: [`0 1 443 ${info.mailServerHostname}.`]
            },
            {
                name: `_carddavs._tcp.${info.mailDomain}.`,
                type: 'TXT',
                content: [`"path=/SOGo/dav/"`]
            },
            {
                name: `_caldavs._tcp.${info.mailDomain}.`,
                type: 'TXT',
                content: [`"path=/SOGo/dav/"`]
            }
        ]
    }

    /**
     * This will add:
     *  - Mailcow: 
     *      - Domain (if not present)
     *      - Mailbox (if not present)
     *      - DKIM Key (if not present)
     *      - Alias: catchall (catchall will relay everything @yourdomain.tld to your Mailbox) (if not present)
     *  - PowerDns: 
     *      - Domain (if not present)
     *      - Mail records for the domain (won't touch other records but will overwrite present matching records)
     *      - DNSSEC (if domain wasn't present)
     *      - Create record on mailServerDomain(if not the same as mailDomain) to allow dmarc mails to sent to this domain
     * @param {Info} info {@link DOC_URL/global.html#Info Info} object with the necessary information to create a mail domain on mailcow and the necessary records on powerdns
     * @param {Boolean} [log=true] you can disable logging by setting this to false
     * @async
     * @returns {Boolean} true on success
     * @example
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
     */
    addMailDomain = async (info, log = true) => {
        info.domain = info.mailDomain;
        if (log) {
            console.log(`Adding zone ${info.mailDomain} to PowerDns if it doesn't exist`);
            console.log(`Adding domain ${info.mailDomain} to Mailcow if it doesn't exist`);
            console.log(`Adding DKIM key for ${info.mailDomain} to Mailcow if it doesn't exist`);
        }
        const add = await Promise.all([this.pdns.createAndSetupZone(info), this.mcc.addDomain(info.mailDomain), this.mcc.addAndGetDKIM(info.mailDomain)]);

        console.log(`You have to add the following key to your domain at your registrar (where you bought the domain)`);
        console.log(add[0]);

        if (log) {
            console.log(`Generating mail domain records for ${info.mailDomain}`);
        }
        const records = this.genMailDomainRecords(info);

        records.push({
            name: `dkim._domainkey.${info.mailDomain}.`,
            type: 'TXT',
            content: [`"${add[2].dkim_txt}"`]
        });

        if (info.dmarcMail && info.mailDomain !== info.dmarcMail.match(secondLevelRegex)[0]) {
            if (log) {
                console.log(`Adding record to DMARC mail domain ${info.dmarcMail.match(secondLevelRegex)[0]} to allow the sending of ${info.mailDomain} DMARC reports there`);
            }
            this.pdns.setHomogeneousRecords([{
                name: `${info.mailDomain}._report._dmarc.${info.dmarcMail.match(secondLevelRegex)[0]}`,
                type: 'TXT',
                content: [`"v=DMARC1"`]
            }]).catch(e => console.log(e))
        }
        if (log) {
            console.log(`Adding generated records to PowerDns server`);
            console.log(`Adding mailbox to Mailcow server`);
        }
        const b = await Promise.all([
            this.pdns.setHomogeneousRecords(records).catch(e => console.log(e)),
            this.mcc.addMailbox({
                domain: info.mailDomain,
                name: info.defaultMailbox.name,
                local_part: info.defaultMailbox.local_part,
                password: info.defaultMailbox.password ? info.defaultMailbox.password : undefined
            })
        ]);

        if (log) {
            console.log(`Adding catchall alias to ${info.mailDomain}`);
        }
        this.mcc.addAlias(`@${info.mailDomain}`, `${info.defaultMailbox.local_part}@${info.mailDomain}`);
        if (!info.defaultMailbox.password) {
            console.log(`The password for your mailbox is`);
            console.log(b[1].password);
        }
        if (log) {
            console.log(`Done adding domain ${info.mailDomain}`);
        }
        console.log(`Don't forget to add the DNSSEC domainkey above to your registrar.`);
        return true;

    }

    /**
     * This will add:
     *  - PowerDns: 
     *      - Domain for the mailserver hostname (if not present)
     *      - DNSSEC (will replace old dnssec if present)
     *      - TLSA records for the domain (for the creation of the tlsa records you need to have openssl installed. you can specify the path, if it can't be found globally as 'openssl')
     *      - Records for the mailserver
     * @param {Info} info {@link DOC_URL/global.html#Info Info} object with the necessary information to create the relevant records for the mailserver
     * @param {Boolean} [log=true] you can disable logging by setting this to false
     * @async
     * @returns {Boolean} true on success
     * @example
     */
    addMailServerDnsRecords = async (info, log = true) => {
        info.domain = info.mailServerHostname
        if (log) {
            console.log(`Adding zone ${info.mailServerHostname} to PowerDns if it doesn't exist`);
        }
        const z = await this.pdns.createAndSetupZone(info).catch(e => {
            console.log(e);
        });

        console.log(`You have to add the following key to your domain at your registrar (where you bought the domain)`);
        console.log(z);

        if (log) {
            console.log(`Creating TLSA records for your mail server domain.`);
            console.log(`Info: You need to have openssl installed for this to work`);
            console.log(`Info: If openssl is not accessible throug the global command 'openssl' you can specify the path by adding it to the passed info object with the key 'openssl_path' for more information look here DOC_URL/global.html#Info`);
        }
        const records = (await this.getTLSA(info)).map((e) => {
            return e.dns
        });
        if (log) console.log(`Adding mail server ip records`);

        if (info.mailServerLegacyIp) {
            records.push({
                name: info.mailServerHostname,
                type: 'A',
                content: [info.mailServerLegacyIp]
            });
        }
        if (info.mailServerIp) {
            records.push({
                name: info.mailServerHostname,
                type: 'AAAA',
                content: [info.mailServerIp]
            });
        }
        if (info.addLetsEncryptCAA) {
            if (log) console.log(`Adding mail server caa records`);

            const content = [`0 issue "digicert.com"`, `0 issue "letsencrypt.org"`];
            info.caaReportMail ? content.push(`0 iodef "mailto:${info.caaReportMail}"`) : '';
            records.push({
                name: info.mailServerHostname.match(secondLevelRegex)[0],
                type: 'CAA',
                content: content
            });
        }
        if (log) console.log(`Setting all records on the PowerDns server`);

        this.pdns.setHomogeneousRecords(records).catch(e => {
            console.log(e);
        });
        if (log) console.log(`Finished adding records for the mail server ${info.mailServerHostname}`);
        console.log(`Don't forget to add the DNSSEC domainkey above to your registrar.`);

        return true;

    }

    /**
     * Creates the front part of the openpgp dns record
     * @param {String} localPart local part of your email address (the part before the @ not including the @)
     * @example
       console.log(openpgpHash('max.mustermensch'));
     */
    openpgpHash = (localPart) => {
        return crypto.createHash('sha256').update(localPart).digest('hex').substr(0, 56);
    }

    /**
     * Creates an openpgp dns record
     * @param {String} localPart local part of your email address (the part before the @ not including the @)
     * @param {String} publicKeyB64 your publickey in base64 (it should be correct if it includes -----BEGIN PGP PUBLICKEY BLOCK-----) or only contains these characters: A-Z a-z 0-9 + /
     * @returns {OpenpgpRecord}
     * @example
       console.log(openpgpRecord('max.mustermensch','-----BEGIN PGP (...)'));
     */
    openpgpRecord = (localPart, publicKeyB64) => {
        const c = publicKeyB64.replaceAll(/[\n\r\s]*/g, '').replace('-----BEGINPGPPUBLICKEYBLOCK-----', '').replace('-----ENDPGPPUBLICKEYBLOCK-----', '').match(/^[A-Za-z0-9+/]*/)[0];
        if (!c) throw Error('Invalid Public Key')
        return {
            name: `${this.openpgpHash(localPart)}._openpgpkey.`,
            type: `OPENPGPKEY`,
            content: [c]
        }
    }

    /**
     * Sets an openpgp record on your powerdns server
     * Will overwrite key with the same local part
     * @param {String} localPart local part of your email address (the part before the @ not including the @)
     * @param {String} domain the domain you want to add the key to
     * @param {String} publicKeyB64 your publickey in base64 (it should be correct if it includes -----BEGIN PGP PUBLICKEY BLOCK-----) or only contains these characters: A-Z a-z 0-9 + /
     * @async
     * @example
       console.log(setOpenpgpRecord('max.mustermensch','domain.tld','-----BEGIN PGP (...)'));
     */
    setOpenpgpRecord = async (localPart, domain, publicKeyB64) => {
        const record = this.openpgpRecord(localPart, publicKeyB64);
        record.name = record.name + domain;
        await this.pdns.setRecords([record]).catch(e => console.log(e));
    }

    /**
     * Will delete the complete mailserver domain from powerdns
     * @param {Info} info {@link DOC_URL/global.html#Info Info} object with the necessary information to delete the mailserver domain 
     * @async
     * @example
        cleanupAddMailServer({mailServerHostname:'mail.domain.tld'});
     */
    cleanupAddMailServer = async (info) => {
        await this.pdns.deleteZone(info.mailServerHostname);
    }

    /**
     * Will delete a domain from powerdns and mailcow
     * THIS WILL DELETE YOUR MAILBOX AND EVERYTHING ELSE CONCERNING THIS DOMAIN
     * @param {Info} info {@link DOC_URL/global.html#Info Info} object with the necessary information to create a mail domain on mailcow and the necessary records on powerdns
     * @async
     * @example
         await pk.cleanupAddMailDomain({
             dmarcMail: 'postmaster@domain.tld', 
             mailDomain: 'domain.tld',
             defaultMailbox: {
                 local_part: `max.mustermensch`,
                 name: `Max Mustermensch`
             }
         });
     */
    cleanupAddMailDomain = async (info) => {
        await this.mcc.deleteMailbox(`${info.defaultMailbox.local_part}@${info.mailDomain}`).catch(e => console.log(e));
        await Promise.all([
            this.mcc.deleteDomain(info.mailDomain),
            this.mcc.deleteDKIM(info.mailDomain),
            this.pdns.deleteZone(info.mailDomain),
        ]);
        if (info.dmarcMail && info.mailDomain !== info.dmarcMail.match(secondLevelRegex)[0]) {
            this.pdns.deleteRecords([{
                name: `${info.mailDomain}._report._dmarc.${info.dmarcMail.match(secondLevelRegex)[0]}`,
                type: 'TXT'
            }]).catch(e => console.log(e));
        }
    }
}