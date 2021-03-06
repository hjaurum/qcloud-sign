/**
 * Created by aurum on 2018/4/18.
 */
const _ = require('lodash');
const crypto = require('crypto');
const paramError = new Error('缺少参数');

/**
 * 构造函数
 * @param options
 * @param options.secretId 必填
 * @param options.secretKey 必填
 * @constructor
 */
const Sign = function (options) {
    if (!options.secretId || !options.secretKey) {
        throw paramError;
    }
    _.defaults(this, options);
};

module.exports = Sign;

Sign.prototype = {
    /**
     * 计算签名
     * @param params {Object} 必填, 为请求所需参数
     *                        字段名与参数名一致
     *                        比如腾讯云规定参数名Region，则字段名也为Region，注意不要写成首字母region
     * @param params.Nonce {Number} 选填，不传则随机分配一个随机数
     * @param params.Timestamp {Number} 选填，不传则使用当前时间戳
     * @param params.SecretId {String} 建议不传，sdk会根据构造参数自动补充
     * @param params.SignatureMethod {String} 选填，默认为HmacSHA256
     * @param options 对请求的说明
     * @param options.method {String} 必传，请求方法
     * @param options.domain {String} 必传，请求域名
     * @param options.path {String} 必传，请求路径
     * @returns {*} 返回的Signture是未encodeURI的，需要自己处理
     */
    getSignature: function (params, options) {
        if (!options.method || !options.domain || !options.path) {
            throw  paramError;
        }
        if (!/^\//.test(options.path)) { // 处理path以斜杠开头
            options.path = '/' + options.path;
        }
        _.defaults(params, {
            Nonce: Math.floor(Math.random().toFixed(5) * 100000),
            Timestamp: Math.floor(Date.now() / 1000),
            SignatureMethod: 'HmacSHA256', // 签名算法默认Hmac256
            SecretId: this.secretId,
        });

        const outerKeys = _.keys(params);
        const paramArr = [];
        outerKeys.forEach(function (outerKey) {
            const value = params[outerKey];
            if (typeof value === 'object') {
                const innerKeys = _.keys(value);
                innerKeys.forEach(function (innerKey) {
                    outerKey = outerKey.replace('_', '.');
                    paramArr.push(outerKey + '.' + innerKey + '=' + value[innerKey]);
                });
            } else {
                // 若输入参数的 Key 中包含下划线，则需要将其转换为“.”
                // 但是 Value 中的下划线则不用转换
                // 如 Placement_Zone=CN_GUANGZHOU
                // 则需要将其转换成 Placement.Zone=CN_GUANGZHOU
                outerKey = outerKey.replace('_', '.');
                paramArr.push(outerKey + '=' + value);
            }
        });
        const paramStr = paramArr.sort().join('&');

        const method = options.method.toUpperCase();
        const signatureStr = method + options.domain + options.path + '?' + paramStr;
        const signatureMathod = params.SignatureMethod === 'HmacSHA256' ? 'sha256' : 'sha1';
        const signature = crypto.createHmac(signatureMathod, this.secretKey).update(signatureStr).digest('base64');

        // 返回对象
        const returnObj = {};
        paramArr.forEach(function (paramPair) {
            const pair = paramPair.split('=');
            returnObj[pair[0]] = pair[1];
        });
        returnObj.Signature = signature;

        return returnObj;
    }
};
