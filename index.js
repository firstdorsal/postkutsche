"use strict";

const exec = require(`util`).promisify(require(`child_process`).exec);
const secondLevelRegex = new RegExp(/[A-Z-a-z0-9]{1,63}\.[A-Z-a-z0-9]{1,63}$/);
const crypto = require('crypto');



const {
    MailcowApiClient
} = require("mailcow-api")
const {
    PowerdnsClient
} = require('@firstdorsal/powerdns-api');

module.exports.Postkutsche = class {
    constructor(info) {
        this.mcc = new MailcowApiClient(info.mailcow.url, info.mailcow.apikey);
        this.pdns = new PowerdnsClient(info.powerdns.url, info.powerdns.apikey);
    }

    getTLSA = async (info) => {
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
        openssl s_client -servername ${info.mailServerHostname} -connect ${info.mailServerIp?info.mailServerIp:info.mailServerLegacyIp}:${e.port} ${e.starttls?`-starttls `+e.starttls.type:``} 2>/dev/null | 
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
                content: [`"v=DMARC1;p=reject;sp=reject;${info.postmasterEmail?"rua=mailto:"+info.postmasterEmail+";ruf=mailto:"+info.postmasterEmail+";":""}adkim=s;aspf=s;"`]
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

    addMailDomain = async (info) => {
        info.domain = info.mailDomain;
        const add = await Promise.all([this.pdns.createAndSetupZone(info), this.mcc.addDomain(info.mailDomain), this.mcc.addAndGetDKIM(info.mailDomain)]);
        const records = this.genMailDomainRecords(info);
        records.push({
            name: `dkim._domainkey.${info.mailDomain}.`,
            type: 'TXT',
            content: [`"${add[2].dkim_txt}"`]
        });
        if (info.dmarcMail && info.mailDomain !== info.dmarcMail.match(secondLevelRegex)[0]) {
            this.pdns.setHomogeneousRecords([{
                name: `${info.mailDomain}._report._dmarc.${info.dmarcMail.match(secondLevelRegex)[0]}`,
                type: 'TXT',
                content: [`"v=DMARC1"`]
            }]).catch(e => console.log(e))
        }


        await Promise.all([
            this.pdns.setHomogeneousRecords(records).catch(e => console.log(e)),
            this.mcc.addMailbox({
                domain: info.mailDomain,
                name: info.defaultMailbox.name,
                local_part: info.defaultMailbox.local_part,
                password: info.defaultMailbox.password ? info.defaultMailbox.password : undefined
            })
        ]);
        this.mcc.addAlias(`@${info.mailDomain}`, `${info.defaultMailbox.local_part}@${info.mailDomain}`)
    }





    addMailServerDnsRecords = async (info) => {
        info.domain = info.mailServerHostname
        await this.pdns.createAndSetupZone(info).catch(e => {
            console.log(e);
        });
        const records = (await this.getTLSA(info)).map((e) => {
            return e.dns
        });
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
            const content = [`0 issue "digicert.com"`, `0 issue "letsencrypt.org"`];
            info.caaReportMail ? content.push(`0 iodef "mailto:${info.caaReportMail}"`) : '';
            records.push({
                name: info.mailServerHostname.match(secondLevelRegex)[0],
                type: 'CAA',
                content: content
            });
        }
        this.pdns.setHomogeneousRecords(records).catch(e => {
            console.log(e);
        });
    }

    openpgpHash = (string) => {
        return crypto.createHash('sha256').update(string).digest('hex').substr(0, 56);
    }

    openpgpRecord = (local_part, publicKeyB64) => {

        const c = publicKeyB64.replaceAll(/[\n\r\s]*/g, '').replace('-----BEGINPGPPUBLICKEYBLOCK-----', '').replace('-----ENDPGPPUBLICKEYBLOCK-----', '').match(/^[A-Za-z0-9+/]*/)[0];
        if (!c) throw Error('Invalid Public Key')
        return {
            name: `${this.openpgpHash(local_part)}._openpgpkey.`,
            type: `OPENPGPKEY`,
            content: [c]
        }
    }
    setOpenpgpRecord = async (local_part, domain, publicKeyB64) => {

        const record = this.openpgpRecord(local_part, publicKeyB64);
        record.name = record.name + domain;
        await this.pdns.setRecords([record]).catch(e => console.log(e))
    }


    cleanupAddMailServer = async (info) => {
        await this.pdns.deleteZone(info.mailServerHostname)
    }

    cleanupAddMailDomain = async (info) => {
        await this.mcc.deleteMailbox(`${info.defaultMailbox.local_part}@${info.mailDomain}`).catch(e => console.log(e))

        await Promise.all([
            this.mcc.deleteDomain(info.mailDomain),
            this.mcc.deleteDKIM(info.mailDomain),
            this.pdns.deleteZone(info.mailDomain),
        ]);

        if (info.dmarcMail && info.mailDomain !== info.dmarcMail.match(secondLevelRegex)[0]) {
            this.pdns.deleteRecords([{
                name: `${info.mailDomain}._report._dmarc.${info.dmarcMail.match(secondLevelRegex)[0]}`,
                type: 'TXT'
            }]).catch(e => console.log(e))
        }

    }


}