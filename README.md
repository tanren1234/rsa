<h1 align="center"> tanren1234/rsa </h1>

<p align="center"> rsa数据加解密，生成签名，验证签名</p>


## Installing

```shell
$ composer require tanren1234/rsa:dev-master -vvv
```

## Usage

#### 生成公私钥
- 如果报下面的错就需要设置config路径
> Warning: openssl_pkey_export(): cannot get key from parameter 1
```php
require __DIR__ .'/vendor/autoload.php';
use Rsa\GenerateSecretKey;
$client = new GenerateSecretKey();
$client->setOpensslPath('D:\phpstudy_pro\Extensions\php\php7.3.4nts\extras\ssl\openssl.cnf');
var_dump($client->generate());
```
#### 数据加解密
```php
require __DIR__ .'/vendor/autoload.php';
use Rsa\RsaClient;

// 生成的私钥
$privatePEMKey="xxxxx";

// 生成的公钥
$publicPEMKey = "xxxxx";

// 需要加密的字符串
$str ="213232";

$rsa = new RsaClient();
$rsa->rsaPublicKey =$publicPEMKey;
$rsa->rsaPrivateKey = $privatePEMKey;
$encrypted = $rsa->publicEncryptRsa($str);
var_dump($encrypted); // 加密数据
$decrypted = $rsa->privateDecryptRsa($encrypted);
var_dump($decrypted); // 解密后的数据
```

#### 备注
> 加解密均采用分段的方式，数据量过大必须使用分段
- 生成公私钥的字节为2048 要加密的最大字符数（字节）=2048/8-11（使用填充时）=245个字符
- 生成公私钥的字节为2048 要解密的最大字符数（字节）=2048/8（使用填充时）=256个字符

### 新增java版解密 java目录

### golang版加解密 go目录
## Contributing

You can contribute in one of three ways:

1. File bug reports using the [issue tracker](https://github.com/tanren1234/rsa/issues).
2. Answer questions or fix bugs on the [issue tracker](https://github.com/tanren1234/rsa/issues).
3. Contribute new features or update the wiki.

_The code contribution process is not very formal. You just need to make sure that you follow the PSR-0, PSR-1, and PSR-2 coding guidelines. Any new code contributions must be accompanied by unit tests where applicable._

## License

MIT
