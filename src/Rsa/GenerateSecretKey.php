<?php
namespace Rsa;
/**
 * 生成公私钥
 * Class GenerateSecretKey
 */
class GenerateSecretKey
{

    protected $digest_alg = "sha512";
    protected $private_key_bits = 2048;
    protected $private_key_type = OPENSSL_KEYTYPE_RSA;
    protected $openssl_path;
    protected $config = array();

    public function __construct(array $config = [])
    {
        $init_config = array(
            'digest_alg' => $this->digest_alg,
            'private_key_bits' => $this->private_key_bits,
            'private_key_type' => $this->private_key_type
        );
        if ($config) {
            if (isset($config['digest_alg'])) {
                $init_config['digest_alg'] = $config['digest_alg'];
            }
            if (isset($config['private_key_bits'])) {
                $init_config['private_key_bits'] = $config['private_key_bits'];
            }
            if (isset($config['private_key_type'])) {
                $init_config['private_key_type'] = $config['private_key_type'];
            }
            if (isset($config['config'])) {
                $init_config['config'] = $config['config'];
            }
        }
        $this->config = $init_config;
    }

    /**
     * 设置openssl_path路径
     * @param string $path
     * @return string
     */
    public function setOpensslPath(string $path)
    {
        $this->openssl_path = $path;
    }

    /**
     * 获取配置参数
     * @return array
     */
    private function getConfig(): array
    {
        $config = $this->config;

        if ($this->openssl_path) {
            $config['config'] = $this->openssl_path;
        }

        return $config;
    }

    /**
     * 生成公私钥
     * @return array
     */
    public function generate(): array
    {
        $config = $this->getConfig();
        
        $res = openssl_pkey_new($config);

        if (isset($config['config'])) {
            openssl_pkey_export($res, $private_key, null, $config);
        } else {
            openssl_pkey_export($res, $private_key);
        }
        $privateKey = $private_key;
        $public_key = openssl_pkey_get_details($res);

        return array(
            'private_key' => $privateKey,
            'public_key' => $public_key['key']
        );
    }
}