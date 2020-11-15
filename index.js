"use strict";

const {
    resolve
} = require(`path`);
const util = require(`util`);
const exec = util.promisify(require(`child_process`).exec);

require('dotenv').config();
const MAILSERVER_DOMAIN = process.env.MAILSERVER_DOMAIN
const USE_LEGACY = process.env.USE_LEGACY
const MAILSERVER_IP6 = process.env.MAILSERVER_IP6
const MAILSERVER_IP4 = process.env.MAILSERVER_IP4
const MAIL_DOMAIN = process.env.MAIL_DOMAIN
const MAILSERVER_IP = USE_LEGACY ? MAILSERVER_IP4 : MAILSERVER_IP6;



const tlsaQuestions = [{
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

const askTLSA = async (questions) => {
    const answers = await Promise.all(questions.map((e) => {
        e.answer = exec(`
        echo | 
        openssl s_client -servername ${MAILSERVER_DOMAIN} -connect ${MAILSERVER_IP}:${e.port} ${e.starttls?`-starttls `+e.starttls.type:``} 2>/dev/null | 
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
            fullName: `_${e.port}._tcp.${MAILSERVER_DOMAIN}`,
            name: `_${e.port}._tcp`,
            type: `tlsa`,
            value: `3 1 1 ${sha256}`
        }
    });
    return questions;
}

const generateMailRecords = (mailServerDomain, mailDomain, spfSettings = {
    spfQualifier: 'FAIL',
    spfMechanism: 'MX'
}) => {

    const SPF_QUALIFIERS = {
        PASS: `+`,
        NEUTRAL: `?`,
        SOFTFAIL: `~`,
        FAIL: `-`
    };
    const SPF_MECHANISMS = [`ALL`, `A`, `IP4`, `IP6`, `MX`, `PTR`, `EXISTS`, `INCLUDE`]
    return [{
            reverseDns: {
                fullName: MAILSERVER_IP6.replace('[', '').replace(']', ''),
                type: `PTR`,
                value: mailServerDomain
            }
        }, {
            reverseDns: {
                //fullName: MAILSERVER_IP4.replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/gm, `$4.$3.$2.$1.in-addr.arpa`),
                fullName: MAILSERVER_IP4,
                type: `PTR`,
                value: mailServerDomain
            }
        }, {
            dns: {
                fullName: mailServerDomain,
                name: `@`,
                type: `AAAA`,
                value: MAILSERVER_IP6.replace('[', '').replace(']', '')
            }
        }, {
            dns: {
                fullName: mailServerDomain,
                name: `@`,
                type: `A`,
                value: MAILSERVER_IP4
            }
        }, {
            dns: {
                fullName: mailDomain,
                name: `@`,
                type: `MX`,
                value: mailServerDomain
            }
        }, {
            dns: {
                fullName: `autodiscover.${mailDomain}`,
                name: `autodiscover`,
                type: `CNAME`,
                value: mailServerDomain
            }
        }, {
            dns: {
                fullName: `autoconfig.${mailDomain}`,
                name: `autoconfig`,
                type: `CNAME`,
                value: mailServerDomain
            }
        },
        {
            dns: {
                fullName: `_autodiscover._tcp.${mailDomain}`,
                name: `_autodiscover._tcp`,
                type: `SRV`,
                value: `${mailServerDomain} 443`
            }
        },
        {
            dns: {
                fullName: mailDomain,
                name: `@`,
                type: `TXT`,
                value: `v=spf1 ${spfSettings.spfMechanism} ${SPF_QUALIFIERS[spfSettings.spfQualifier]}all`
            }
        }

    ]

}

//askTLSA(tlsaQuestions).then(res => console.log(res));
console.log(generateMailRecords(MAILSERVER_DOMAIN, MAIL_DOMAIN));