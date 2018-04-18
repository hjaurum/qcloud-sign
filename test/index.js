/**
 * Created by aurum on 2018/4/18.
 */
const Sign = require('../index');
const assert = require('assert');
const sign = new Sign({
    secretId: 'AKIDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA',
    secretKey: 'Gu5t9xGARNpq86cd98joQYCN3Cozk1qA'
});

describe('签名', function () {
    it('签名,ok', function () {
        const signature = sign.getSignature({
            "Action": "DescribeInstances",
            "Nonce": 11886,
            "Region": "ap-guangzhou",
            "SignatureMethod": "HmacSHA256",
            "Timestamp": 1465185768,
            "InstanceIds.0": "ins-09dx96dg"
        }, {
            method: 'get',
            domain: 'cvm.api.qcloud.com',
            path: '/v2/index.php'
        });
        console.log(signature);
        assert.equal(signature.signature, '0EEm/HtGRr/VJXTAD9tYMth1Bzm3lLHz5RCDv1GdM8s=');
    });
});