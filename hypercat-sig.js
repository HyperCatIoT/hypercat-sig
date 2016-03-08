#!/usr/bin/env node
'use strict';
/*jslint node: true */

var NodeRSA = require('node-rsa'),
    fs = require('fs'),
    cliArgs = require('command-line-args'),
    stringify = require('json-stable-stringify');
var options,
    cat,
    privKey,
    pubKey;


var cli = cliArgs([
    { name: 'verbose', type: Boolean, alias: 'v', description: 'Produce debug' },
    { name: 'help', type: Boolean, alias: 'h', description: 'Print usage instructions' },
    { name: 'sign', type: String, description: 'Sign, requires --privkey and --pubkey'},
    { name: 'verify', type: String, description: 'Verify, requires --pubkey'},
    { name: 'pubkey', type: String, description: 'Public key .pem'},
    { name: 'privkey', type: String, description: 'Private key .pem'}
]);

var usage = cli.getUsage({
    header: 'hypercat-sig',
    footer: ''
});

function readFile(path) {
    return fs.readFileSync(path).toString();    // eslint-disable-line no-sync
}

function sorter(a, b) {
    return a.key < b.key ? 1 : -1;
}

// parse arguments
try {
    options = cli.parse();
} catch(err) {
    console.error(usage);
    process.exit(1); // eslint-disable-line no-process-exit
}


// no useful arguments
if ((Object.keys(options).length === 0) || (options.help) ||
    (options.sign && (!options.privkey))) {
    console.error(usage);
    process.exit(1); // eslint-disable-line no-process-exit
}

if (options.privkey) {
    try {
        privKey = new NodeRSA(readFile(options.privkey));
    } catch(e) {
        console.error("Failed to read privkey", options.privkey);
        process.exit(1); // eslint-disable-line no-process-exit
    }
}
if (options.pubkey) {
    try {
        pubKey = new NodeRSA(readFile(options.pubkey));
    } catch(e) {
        console.error("Failed to read pubkey", options.pubkey);
        process.exit(1); // eslint-disable-line no-process-exit
    }
}

if (options.sign) {
    if ((!options.pubkey) || (!options.privkey)) {
        console.error('Public and private keys required, use --pubkey and --privkey');
        process.exit(1);
    }

    fs.readFile(options.sign, 'utf8', function(err, data) {
        if (err) {
            console.error('Failed to read', options.sign);
        } else {
            try {
                cat = JSON.parse(data);

                cat['catalogue-metadata'].push({
                    rel: 'urn:X-hypercat:rels:jws:signature',
                    val: privKey.sign(stringify(cat, sorter)).toString('base64')
                });
                cat['catalogue-metadata'].push({
                    rel: 'urn:X-hypercat:rels:jws:alg',
                    val: 'RS256'
                });
                cat['catalogue-metadata'].push({
                    rel: 'urn:X-hypercat:rels:jws:key',
                    val: pubKey.exportKey('pkcs8-public-pem')
                });
                console.log(JSON.stringify(cat, null, 2));
            } catch(e) {
                console.error('Invalid Hypercat', options.sign, e);
            }
        }
    });
}

function getMetadataRel(mdata, rel) {
    var i;
    for (i = 0; i < mdata.length; i += 1) {
        if (mdata[i].rel === rel) {
            return mdata[i].val;
        }
    }
    return null;
}

function catRemoveSig(inCat) {
    var i;
    var mdata;
    var outCat = {
        'catalogue-metadata': []
    };

    // copy everything but jws rels across
    mdata = inCat['catalogue-metadata'];
    for (i = 0; i < mdata.length; i += 1) {
        if (mdata[i].rel.indexOf('urn:X-hypercat:rels:jws') !== 0) {
            outCat['catalogue-metadata'].push(mdata[i]);
        }
    }

    // for now, copy entire items, as we only deal with header signing
    outCat.items = inCat.items;

    return outCat;
}

if (options.verify) {
    if (!options.pubkey) {
        console.error('No public key provided, use --pubkey');
        process.exit(1);
    }
    fs.readFile(options.verify, 'utf8', function(err, data) {
        if (err) {
            console.error('Failed to read', options.sign);
        } else {
            try {
                cat = JSON.parse(data);
                if (pubKey.verify(stringify(catRemoveSig(cat), sorter), new Buffer(getMetadataRel(cat['catalogue-metadata'], 'urn:X-hypercat:rels:jws:signature'), 'base64'))) {
                    console.log("Verify OK");
                } else {
                    console.log("Verify failed");
                }
            } catch(e) {
                console.error('Invalid Hypercat', options.sign, e);
            }
        }
    });
}

