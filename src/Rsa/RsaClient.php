<?php
namespace Rsa;
/**
 * Created by PhpStorm.
 * User: tr
 * Date: 2020/5/27
 * Time: 10:48
 */
class RsaClient
{
    // 私钥文件路径
    public $rsaPrivateKeyFilePath;

    // 私钥值
    public $rsaPrivateKey;

    // 公钥文件路径
    public $rsaPublicKeyFilePath;

    // 公钥值
    public $rsaPublicKey;

    /**
     * 生成签名
     * @param $params
     * @return string
     */
    public function rsaSign($params)
    {
        return $this->sign($this->getSignContent($params));
    }

    /**
     * 验证签名
     * @param $params
     * @param $sign
     * @return bool
     */
    public function rsaVerifySign($params, $sign)
    {
        return $this->verifySign($this->getSignContent($params), $sign);
    }

    /**
     * 通过私钥生成签名
     * @param $data
     * @return string
     */
    public function sign($data) : string
    {
        $res = $this->getPrivateKey();

        if (!$res) return "";

        openssl_sign($data, $sign, $res, OPENSSL_ALGO_SHA256);

        if (!$this->checkEmpty($this->rsaPrivateKeyFilePath)) {
            openssl_free_key($res);
        }
        $sign = base64_encode($sign);
        return $sign;
    }

    /**
     * 获取签名字符串
     * @param $params
     * @return string
     */
    public  function getSignContent($params)
    {
        ksort($params);
        reset($params);
        $stringToBeSigned = "";
        $i = 0;
        foreach ($params as $k => $v) {
            if (false === $this->checkEmpty($v)) {
                if ($i == 0) {
                    $stringToBeSigned .= "$k" . "=" . "$v";
                } else {
                    $stringToBeSigned .= "&" . "$k" . "=" . "$v";
                }
                $i++;
            }
        }

        unset ($k, $v);
        return $stringToBeSigned;
    }

    /**
     * 公钥验证签名
     * @param $data
     * @param $sign
     * @return bool
     */
    public  function verifySign($data, $sign) : bool
    {
        $res = $this->getPublicKey();

        if (!$res) return false;

        //调用openssl内置方法验签，返回bool值
        $result = (openssl_verify($data, base64_decode($sign), $res, OPENSSL_ALGO_SHA256) === 1);

        if (!$this->checkEmpty($this->rsaPublicKeyFilePath)) {
            //释放资源
            openssl_free_key($res);
        }

        return $result;
    }

    /**
     * 校验$value是否非空
     * @param $value
     * @return bool
     */
    protected function checkEmpty($value)
    {
        if (!isset($value))
            return true;
        if ($value === null)
            return true;
        if (trim($value) === "")
            return true;

        return false;
    }

    /**
     * @return false|resource|string
     */
    public function getPrivateKey()
    {
        if ($this->checkEmpty($this->rsaPrivateKeyFilePath)) {
            $priKey = $this->rsaPrivateKey;
            if (strpos($priKey,'-----') !== false) {
                $res = $priKey;
            }else{
                $res = "-----BEGIN RSA PRIVATE KEY-----\n" .
                    wordwrap($priKey, 64, "\n", true) .
                    "\n-----END RSA PRIVATE KEY-----";
            }
        } else {
            $priKey = file_get_contents($this->rsaPrivateKeyFilePath);
            $res = openssl_get_privatekey($priKey);
        }
        return $res;
    }

    /**
     * @return false|resource|string
     */
    public function getPublicKey()
    {
        if ($this->checkEmpty($this->rsaPublicKeyFilePath)) {

            $pubKey = $this->rsaPublicKey;
            if (strpos($pubKey,'-----') !== false) {
                $res = $pubKey;
            }else{
                $res = "-----BEGIN PUBLIC KEY-----\n" .
                    wordwrap($pubKey, 64, "\n", true) .
                    "\n-----END PUBLIC KEY-----";
            }

        } else {
            //读取公钥文件
            $pubKey = file_get_contents($this->rsaPublicKeyFilePath);
            //转换为openssl格式密钥
            $res = openssl_get_publickey($pubKey);
        }
        return $res;
    }

    /**
     * 返回私钥的长度 512 1024 2408
     * @return mixed
     */
    public function getPrivateKenLen()
    {
        $pub_id = openssl_get_privatekey($this->getPrivateKey());

        return openssl_pkey_get_details($pub_id)['bits'];
    }
    /**
     * 返回公钥的长度 512 1024 2408
     * @return mixed
     */
    public function getPublicKenLen()
    {
        $pub_id = openssl_get_publickey($this->getPublicKey());

        return openssl_pkey_get_details($pub_id)['bits'];
    }
    /**
     * RSA私钥加密数据
     * @param $plainData
     * @return bool|string
     */
    function privateEncryptRsa($plainData = '')
    {
        if (!is_string($plainData)) {
            return null;
        }
        $encrypted = '';

        $partLen = $this->getPrivateKenLen()/8 - 11;

        $plainData = str_split($plainData, $partLen);

        $privatePEMKey = $this->getPrivateKey();

        foreach ($plainData as $chunk) {
            $partialEncrypted = '';

            //using for example OPENSSL_PKCS1_PADDING as padding
            $encryptionOk = openssl_private_encrypt($chunk, $partialEncrypted, $privatePEMKey, OPENSSL_PKCS1_PADDING);

            if ($encryptionOk === false) {
                return false;
            }//also you can return and error. If too big this will be false
            $encrypted .= $partialEncrypted;
        }
        return base64_encode($encrypted);//encoding the whole binary String as MIME base 64
    }
    /**
     * RSA公钥加密数据
     * @param $plainData
     * @return bool|string
     */
    function publicEncryptRsa($plainData = '')
    {
        if (!is_string($plainData)) {
            return null;
        }

        $encrypted = '';

        $partLen = $this->getPublicKenLen()/8 - 11;

        $plainData = str_split($plainData, $partLen);

        $publicPEMKey = $this->getPublicKey();

        foreach ($plainData as $chunk) {
            $partialEncrypted = '';

            //using for example OPENSSL_PKCS1_PADDING as padding
            $encryptionOk = openssl_public_encrypt($chunk, $partialEncrypted, $publicPEMKey, OPENSSL_PKCS1_PADDING);

            if ($encryptionOk === false) {
                return false;
            }//also you can return and error. If too big this will be false
            $encrypted .= $partialEncrypted;
        }
        return base64_encode($encrypted);//encoding the whole binary String as MIME base 64
    }
    /**
     * 私钥解密数据
     * @param $data
     * @return bool|string
     */
    public function privateDecryptRsa($data = '')
    {
        if (!is_string($data)) {
            return null;
        }
        $decrypted = '';

        $partLen = $this->getPrivateKenLen() / 8;
        //decode must be done before spliting for getting the binary String
        $data = str_split(base64_decode($data), $partLen);

        $privatePEMKey = $this->getPrivateKey();

        foreach ($data as $chunk) {
            $partial = '';

            //be sure to match padding
            $decryptionOK = openssl_private_decrypt($chunk, $partial, $privatePEMKey, OPENSSL_PKCS1_PADDING);

            if ($decryptionOK === false) {
                return false;
            }//here also processed errors in decryption. If too big this will be false
            $decrypted .= $partial;
        }
        return $decrypted;
    }
    /**
     * 公钥解密数据
     * @param $data
     * @return bool|string
     */
    public function publicDecryptRsa($data = '')
    {
        if (!is_string($data)) {
            return null;
        }

        $decrypted = '';

        $partLen = $this->getPublicKenLen() / 8;
        //decode must be done before spliting for getting the binary String
        $data = str_split(base64_decode($data), $partLen);

        $publicPEMKey = $this->getPublicKey();

        foreach ($data as $chunk) {
            $partial = '';

            //be sure to match padding
            $decryptionOK = openssl_public_decrypt($chunk, $partial, $publicPEMKey, OPENSSL_PKCS1_PADDING);

            if ($decryptionOK === false) {
                return false;
            }//here also processed errors in decryption. If too big this will be false
            $decrypted .= $partial;
        }
        return $decrypted;
    }
}
