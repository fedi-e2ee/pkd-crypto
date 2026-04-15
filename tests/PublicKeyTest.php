<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\EncodingException;
use FediE2EE\PKD\Crypto\Exceptions\InvalidSignatureException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use ParagonIE\PQCrypto\Exception\MLDSAInternalException;
use ParagonIE\PQCrypto\Exception\PQCryptoCompatException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use ReflectionClass;
use ReflectionException;
use SodiumException;

#[CoversClass(PublicKey::class)]
class PublicKeyTest extends TestCase
{
    public static function knownAnswersMultibase(): array
    {
        $mldsa = 'mldsa44:9R3VB-DV8IGP4szUw3j-E8KKm3C_-VMej8l4UiDJVW2_2yfCgcaizSOgdM-QioheqmhXGi3xbWYEb83OB3shT3MxUaxgUoD8FEUB4Oj5JMXR5O_jen6ZM91UEBJwn5Ek5fPnbgnBMnWFl5EPK6_2Of-WwDTdFpanqJdai-L9P6O8GAioRDXU9lTASUzqb1_dQ2k1huvmo5rIzgCekShV9GyyhxRTnZwPDqLwghsAooOr1fPLtx_Baz_2vIa8_IJlA4QFSaabCINNjWobAO3pM9aCxApewO3ft-coSrv-WMrOZ3gJpSwwmrRJ3hsRvxoJIvZt11pkF-SOlbMmDqQA__HHpjZEyzixFwHBUC8xb4H5TO1ZYATrqOpemYE8SY-9keIZduqr7xlNQ1STZ0-Tfmk60H4x8_R1ZIkI-JPJtwRmNW1-Qnl7OyYw2OZEnOtH7CFwjcSFORtMBoeDoUD4SQj7wNPC9y7rNDxfU8k6XuE7JajE6ERofZL4rDXJHi3TIlVQVVihe57X8sYNa7RlqO3-JoCGr05HbHuTrWO5659cQDkwR7GLZd6K_th2TW6RKXn9DQxN9LUlK3dTe6f-Pp4rZcQgu9eU1rrkKD9s34Slh3O_EuVGAa-iVJ7m9IGB22_UulEQooLoGLlegy3M0LVD8Au9qjqie0ULFkr027hDpBvQZnEpznGv22KCoRPBrc0bSHLItHiZRGK9QFWty316q6vLjn4whNGglKWp18i6I38_e4sD84FZg1kewpYB4jd456fhbQcQm6DNRwqHsNvPL6MeUK-9rmEwIhJhQIT-aFylbAoch7N6gkjgv3U5irfBdY2r7nBg1odeuiC6tpk6WHd5ou7gVj4I9mDAs_gMUBaCPmLLMLhEdBZItHqfVw4nfFYHkFkg9KRg5ciekQZ25oI0cUqn0Z_f-oQzBr-PSnKzkVVtGGHtfdKCr4thcvnvcH1ks9GKrzYwxDpKO0B9AuPhtu0xYOdPXbHZfjcZInSn0rWLt4BwS_1yFt3jwOURGaPiGqINqMfZ-9Pvv__a0Z1K2zGunGWOAFryrP1ehOywNtAWIuwaim3mocsyEO0OxXkOy0CtlqrYmlfKangGB_mkE9tNOFpdnjZa5MRZirRqE802lGZGxt1uDJPuPiFyL8QyO7ByDBz9uavdrlOl6Yoa409EIANXkWf8yX-c3QAWg1q7c8uzBRSXlUbL3-rfGvCffcfDV9FPgDKC_kROqbJKeSumMoVvyLgszUt-amo0H6sSC4fiCMM9dsDRg5QQgB0bNyZeG54vdUH44qKysvW_MyGCFHtXjfPIV3u50y1UlG4Pg4UIGmMKV3Bpsb4AXcQ-U6UKaf4n-yOwGMeqxiZfJhjsKMKFiFTB7w72cKMGlUY3gtMBaURfTHlgHKB8fubNUbI4jEU8DG90WuGFuOibQkhD4Mcyln9QJDRB6e3uNWXrTfl1eVelJLza1-bVD7lSr8CHMhmEIw-BoQ7pIuQcoUxY4_MFuBhYO-JeaMEyNaYhPziJIVm9rOtFjNu_qANLKxyP2a8NraeL3lC5llF3NNF6xE4fpqEUrcTu4shgqbpmWFkkn6PRK6AStE1wlWmnw2SshjSWSlLUWUh5zOXOqSZQ1vQEv3L9zG6OUiwrsWMEC7IdcwDUndKeEO0geQ4eP6pnpCHmJTuC_hJCKLah0H-kBvmTqRIeqSaHg8LoCrboT1bdrCMLSfVq0cW3VL8LGvEZ3vCPCZw6Fw';
        return [
            ['z6MkvsDmfeVK6FxhjxxqhGvNVYWVxWdcuTa7Ghg5swZJqfFM', 'ed25519:895bv6cvVy1h85m-bt0CG2sjvHpwHb9EyTWXmEZeAKg'],
            ['u7QHz3lu_py9XLWHzmb5u3QIbayO8enAdv0TJNZeYRl4AqA', 'ed25519:895bv6cvVy1h85m-bt0CG2sjvHpwHb9EyTWXmEZeAKg'],
            [
                'uEhD1HdUH4NXwgY_izNTDeP4TwoqbcL_5Ux6PyXhSIMlVbb_bJ8KBxqLNI6B0z5CKiF6qaFcaLfFtZgRvzc4HeyFPczFRrGBSgPwURQHg6PkkxdHk7-N6fpkz3VQQEnCfkSTl8-duCcEydYWXkQ8rr_Y5_5bANN0Wlqeol1qL4v0_o7wYCKhENdT2VMBJTOpvX91DaTWG6-ajmsjOAJ6RKFX0bLKHFFOdnA8OovCCGwCig6vV88u3H8FrP_a8hrz8gmUDhAVJppsIg02NahsA7ekz1oLECl7A7d-35yhKu_5Yys5neAmlLDCatEneGxG_Ggki9m3XWmQX5I6VsyYOpAD_8cemNkTLOLEXAcFQLzFvgflM7VlgBOuo6l6ZgTxJj72R4hl26qvvGU1DVJNnT5N-aTrQfjHz9HVkiQj4k8m3BGY1bX5CeXs7JjDY5kSc60fsIXCNxIU5G0wGh4OhQPhJCPvA08L3Lus0PF9TyTpe4TslqMToRGh9kvisNckeLdMiVVBVWKF7ntfyxg1rtGWo7f4mgIavTkdse5OtY7nrn1xAOTBHsYtl3or-2HZNbpEpef0NDE30tSUrd1N7p_4-nitlxCC715TWuuQoP2zfhKWHc78S5UYBr6JUnub0gYHbb9S6URCigugYuV6DLczQtUPwC72qOqJ7RQsWSvTbuEOkG9BmcSnOca_bYoKhE8GtzRtIcsi0eJlEYr1AVa3LfXqrq8uOfjCE0aCUpanXyLojfz97iwPzgVmDWR7ClgHiN3jnp-FtBxCboM1HCoew288vox5Qr72uYTAiEmFAhP5oXKVsChyHs3qCSOC_dTmKt8F1javucGDWh166ILq2mTpYd3mi7uBWPgj2YMCz-AxQFoI-YsswuER0Fki0ep9XDid8VgeQWSD0pGDlyJ6RBnbmgjRxSqfRn9_6hDMGv49KcrORVW0YYe190oKvi2Fy-e9wfWSz0YqvNjDEOko7QH0C4-G27TFg509dsdl-NxkidKfStYu3gHBL_XIW3ePA5REZo-Iaog2ox9n70--__9rRnUrbMa6cZY4AWvKs_V6E7LA20BYi7BqKbeahyzIQ7Q7FeQ7LQK2WqtiaV8pqeAYH-aQT2004Wl2eNlrkxFmKtGoTzTaUZkbG3W4Mk-4-IXIvxDI7sHIMHP25q92uU6XpihrjT0QgA1eRZ_zJf5zdABaDWrtzy7MFFJeVRsvf6t8a8J99x8NX0U-AMoL-RE6pskp5K6YyhW_IuCzNS35qajQfqxILh-IIwz12wNGDlBCAHRs3Jl4bni91QfjiorKy9b8zIYIUe1eN88hXe7nTLVSUbg-DhQgaYwpXcGmxvgBdxD5TpQpp_if7I7AYx6rGJl8mGOwowoWIVMHvDvZwowaVRjeC0wFpRF9MeWAcoHx-5s1RsjiMRTwMb3Ra4YW46JtCSEPgxzKWf1AkNEHp7e41ZetN-XV5V6UkvNrX5tUPuVKvwIcyGYQjD4GhDuki5ByhTFjj8wW4GFg74l5owTI1piE_OIkhWb2s60WM27-oA0srHI_Zrw2tp4veULmWUXc00XrETh-moRStxO7iyGCpumZYWSSfo9EroBK0TXCVaafDZKyGNJZKUtRZSHnM5c6pJlDW9AS_cv3Mbo5SLCuxYwQLsh1zANSd0p4Q7SB5Dh4_qmekIeYlO4L-EkIotqHQf6QG-ZOpEh6pJoeDwugKtuhPVt2sIwtJ9WrRxbdUvwsa8Rne8I8JnDoX',
                $mldsa
            ],
            [
                'zV9yAZ9HX8F39BZir47iCSWar5ag9rwKND2ggg7bYDb2BV8N8Ps2pRsCjiWzHbcX7YXVpghgLgJuoY9c1eAsraVmputU5Raz3Eb28iFQtQyKvNbtLQdQMpWA3LqyfB5kynJ4xUHNo414rJLKEbGAPnE3nBbYZDmXCAAjiDxfcd3tchJhdhnc7kP1UkWudnyMciqRSHYZQzfKEV3wua7nADPqyUKrFuBF9R8ttZXkcaeWp7iL9iAd9fVQkDvS6QLFLzddbdFvHFwGsimxcnCr6ZLtZtgxdAK4vBLT9fn1eEmYhTZUYdH768BAppSEH4A9Zt2fVMPTdFj3zAKnLR3TXLrqd6UchppzoYJBFpHZzQ4hVD5A8tMyuGps4tZAaqceD66zyu2PQzgJpLUbWysFqmsLUZAaVXCwbok27X3NyvjJMZKAJsrgHV99S52HRieoNPviRVRk8PE1LDhQFZcHeCFeinjRXuCt9zpG9NN33LhBpc7kURD33ryFtMLPqF6FU7XibU992iRzDtUwaYfUBR23Mz3DfVBrrHa9oZCETe7YeD3Zpwktwg26CQZz7CLV2wiC7eurdCdCt3wUQsgPcKCrgbHqTjC5JFKZ2oZwcf9ALaUbGUhSukGML3YREaW28HH14LpwHx4NoGZh2hVh9SoJRwX6q1fjQ52GefTcJNQg2Rs7bQv31S8MvQoPU1v1qCrXYx8uHXNupJCZfZu7nBPnAYg9Kt3nNCbvq542sYFM83o9fAibx3JZuedReHdeUquj5kty76pER4u3GPdC9CEA6huwPt5gqDmPb75jHkAJqZQcf5xLSx5jdDyfB6A3TVN9HgAySoVvSqXpuZ7ufBQmW9LqG9egHC52cMt11P4caJ6VBfrdDTMAzFXkfTj3v1kA9FtPyAehvCMY52Gy5pfT4BFKChpKXTKA1kzwpXt9iyyfvLZ1JR4GLN4PifpHT48uQJHcgoftRCXos59rY1whj2uEhd2auHsaCvyCZeKCM14CzqjjVgnBf5n45CDqW9gsKiahNmRComw5RhXZXLUbfHM2Xeb8yCVy7mysV8Qm1JhipZSS8kp5fbpwaWAyeEReWGtKNgoQ4mTHGv6bHGzW39g9KHXLeDaKZTsGLUirCXYLcCavDDDB2RN92WwLBUqYCNNp7ipjwYFvv8tNvLGhjPSxG4YmtodBo6UsNmJbX3h6VwnXt38LEYZVPt2AcEkw23TsgvQwbb1tmVNL3ETcbgPVrn65NdFvJLHH2YnNnsFQG7pNeff968FtHSrcshfytHbHupNLmb4sLEmPBq8DR6x69mvJQfBQ33hvNmJsv58c9ctwxtuPswiZTkndu9Q6wK8eCD6cvYU1YY7wsez1xkerASsB5VrcoRX9ofoGQvP4FTLuPXGZamCMn45iTQ2njnYuXEfjKpEkcR19AQhZ3dH1YZZiiufSY2poXEzynHJ3o1KjP3c22SWrJjy9W4LLKqJWeq1yU7nH995BjY63MY8pXFvpEyh82Ha7RVWoUXMKN1MkWmKxiBZ9igp3bHs5j7ng8XwqBfa2epudqhNeu6DmUG37Sd1SEtdWhikrtfVAN3wJeWkiND1CbMo9daR23m6NDCr8S8cqj49wNcWQKYLLoXm69Kc9iMvG4ypvBmduTjrwour8r44gT1bH6B4otNt4VJi8UywgDALaUqo3q8CwD7rHahwGjViBFjeza24EZ6TxRZeufsJGSk1fyAizaoLrTDdXvbSyreRfTZgzXTErx411cfpDEUNbCGWxJTSkzJ94AYC1M3LneEPBxCE',
                $mldsa
            ]
        ];
    }

    /**
     * @throws CryptoException
     * @throws EncodingException
     */
    #[DataProvider("knownAnswersMultibase")]
    public function testMultibase(string $input, string $expected): void
    {
        $pk = PublicKey::fromMultibase($input);
        $this->assertSame($expected, $pk->toString());
        $this->assertSame($input, $pk->toMultibase($input[0] === 'z'));
    }

    public function testFromStringInvalid(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Invalid public key: algorithm prefix required');
        PublicKey::fromString('foo');
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testEncodePem(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('phpunit PublicKeyTest.php')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));
        $encoded = $pk->encodePem();
        $expected = "-----BEGIN PUBLIC KEY-----\n" .
            'MCowBQYDK2VwAyEA/oXGYTQRev2uQ5jJvmubXo+moXZFmhKPcnHLFllM0K0=' . "\n" .
        "-----END PUBLIC KEY-----";
        $this->assertSame($expected, $encoded);
    }

    public function testTooShort(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Public key must be 32 bytes');
        PublicKey::fromString('ed25519:foo');
    }

    public function testTooLong(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Public key must be 32 bytes');
        PublicKey::fromString('ed25519:' . str_repeat('A', 100));
    }

    public function testWrongAlgorithm(): void
    {
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Not a valid signing algorithm: ed448');
        PublicKey::fromString('ed448:foo');
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testEncodePemLineLength(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test pem line length')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));
        $encoded = $pk->encodePem();

        // Extract the base64 content lines between header and footer
        $lines = explode("\n", $encoded);
        // Line 0 is "-----BEGIN PUBLIC KEY-----"
        // Line 1 is the base64 content
        // Line 2 is "-----END PUBLIC KEY-----"
        $this->assertCount(3, $lines);
        $this->assertSame('-----BEGIN PUBLIC KEY-----', $lines[0]);
        $base64Line = $lines[1];
        $this->assertSame('-----END PUBLIC KEY-----', $lines[2]);
        $this->assertLessThanOrEqual(64, strlen($base64Line));
        $this->assertNotEmpty($base64Line);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testToMultibaseDefaultUsesBase64(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test multibase default')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));

        $default = $pk->toMultibase();
        $this->assertSame('u', $default[0], 'Default toMultibase should use base64url prefix "u"');
        $explicit = $pk->toMultibase(false);
        $this->assertSame('u', $explicit[0], 'toMultibase(false) should use base64url prefix "u"');
        $this->assertSame($default, $explicit);
        $unsafe = $pk->toMultibase(true);
        $this->assertSame('z', $unsafe[0], 'toMultibase(true) should use base58 prefix "z"');
        $this->assertNotSame($default, $unsafe);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testPemRoundTrip(): void
    {
        $keypair = sodium_crypto_sign_seed_keypair(
            sodium_crypto_generichash('test pem round trip')
        );
        $pk = new PublicKey(sodium_crypto_sign_publickey($keypair));
        $pem = $pk->encodePem();
        $imported = PublicKey::importPem($pem);
        $this->assertSame($pk->getBytes(), $imported->getBytes());
        $this->assertSame($pk->toString(), $imported->toString());
    }

    public static function signatureProvider(): array
    {
        $sk = SecretKey::generate();
        $testCases = [
            [
                $sk,
                'message',
                $sk->sign('message'),
                true,
            ],
        ];

        return $testCases;
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    #[DataProvider("signatureProvider")]
    public function testVerify(
        SecretKey $secretKey,
        string $message,
        string $signature,
        bool $shouldBeValid,
    ): void {
        if (!$shouldBeValid) {
            $this->expectException(InvalidSignatureException::class);
            $secretKey->getPublicKey()->verifyThrow($signature, $message);
        }
        $this->assertSame(
            $shouldBeValid,
            $secretKey->getPublicKey()->verify($signature, $message)
        );
    }

    /**
     * Make sure we can encode/decode successfully
     *
     * @throws CryptoException
     * @throws EncodingException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testMldsa44RandomEncoding(): void
    {
        for ($i = 0; $i < 10; ++$i) {
            $sk = SecretKey::generate('mldsa44');
            $vk = $sk->getPublicKey();
            $mb1 = $vk->toMultibase();
            $mb2 = $vk->toMultibase(true);
            $vk_a = PublicKey::fromMultibase($mb1);
            $vk_b = PublicKey::fromMultibase($mb2);
            $vk_c = PublicKey::fromString($vk->toString());
            $this->assertSame($vk_a->getBytes(), $vk_b->getBytes());
            $this->assertSame($vk_a->getBytes(), $vk_c->getBytes());
            $this->assertSame($vk_b->getBytes(), $vk_c->getBytes());
        }
    }

    /**
     * @throws CryptoException
     * @throws EncodingException
     * @throws MLDSAInternalException
     * @throws NotImplementedException
     * @throws PQCryptoCompatException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testMldsa44(): void
    {

        // Test with deterministic inputs
        $sk2 = new SecretKey(hash('sha256', 'unit testing', true), 'mldsa44');
        $pk2 = $sk2->getPublicKey();
        $expected = '-----BEGIN PUBLIC KEY-----' . "\n" .
            'MIIFNDALBglghkgBZQMEAxEDggUhAJEwoSUGu6xnAen+jPZFwiMZvcj9Pi9eMstZ' . "\n" .
            'LYHFh2Z8FY03MCHLZwbQsfljYRORUWdCSrFDcwz5OfEcOy7P59rs9OfvH8+34M+4' . "\n" .
            'UGV2sJtLMxzkU9+WpIuuEQZXXfKMVtckl3OhWmgK8knDqi3VW2AtkbHxrk4Qilb7' . "\n" .
            '+csogdiFR6p8mTvJvxYHX4RjG42SQonxE1pDjkjLjqk7ubzhg8dzV32ylklz7e9e' . "\n" .
            'D6lqeKM8PrpYV4fXsgqtg38NEplAstkHnfrTAWGhSIC9d78hskON6ZtEYpXfzU5K' . "\n" .
            'mQ+ePpAa+D7hzA12lzzbWKPtGjKxGyi/XXk1BrebME3D3YNwZoIShdLF6VDvX5Cp' . "\n" .
            '0Stfa9o8pHqtAuI3uruKAP8NnWv2amfDXrz3fzPt4a4+JVTQ710l57uiG3QOmAS7' . "\n" .
            'gNIsNHCVaEINQhHAR/95u8RR70PVJWw5Xz7/kVkHECaLdLmbnH2rt3JTPc0ObJRe' . "\n" .
            'tSBiwau+Fc922XvXVg0OmVee1eXzHV6RIhUdGEk4lkds9eGEY6aro2HNqtYT+EsT' . "\n" .
            'Bcr+QW5adLiPPHT0M779oV9c0HQAZqfmOe/S6hkam7gUGDBqARVhayH8TJgakQgV' . "\n" .
            'VZfIAmSq565qHEkYS/HhQ3V8LxbvwoSJl2QF9wqkUlkaOVyVJqbqIh1DSMkocd+J' . "\n" .
            'EnQ1famVENVbZSwrEIY3ydv/UcU243ICVW4exWsZkTMdhFAe6u6OJ/udy0exclrJ' . "\n" .
            'KbdRuf2Tk1jQ8xe8hFRInitoUKujaQp3rO8xOzmtzAe2ajflFyZ0maoxp7z7K4g7' . "\n" .
            '1tMBj2G3u7ef0FU3fMVDt/Lqefs4fQpYM7bAdmODvLpVHUbU3tIzOHPyKiLxlyIR' . "\n" .
            'dSTtKfjc7j9cnY9tSvf6SZpyd+j8Dxf1eMPjLLlrd/qKFOqUCWf6ze26emTmN2yS' . "\n" .
            'lLPmCsuPg15fo4NFeKY0g2BwRjHcZW1ijQx3EAFTu5ZNSgykWBuwMV5PzNA5zYZs' . "\n" .
            'XrUeXcvpL/Q5M6ggjfaUO6SPt5JYKnjJSDODAEpusx9Jp9r1z443K5ejFFAF/OXV' . "\n" .
            '2ocjgG4nPBqK1rjZLA+cgFGTF+Og567bEdkegUrCSBZiw+GSd9xQLrXNMGqLPwLN' . "\n" .
            'UwkqPLd7ebQRcznqc+MXlFN+kMDU5Ar7+TkT0u2UgMomajAMHlfhU2h3nzuFUolt' . "\n" .
            'Vp2BdsEcI9lbtvJEEZiIdGmhNvnwX1dQV+TwlHqntA5NcESvCmir6gNf2adC3hZM' . "\n" .
            'nXk/+EJWW0yicniXgIQh9/ym2NiB4hvbeHVsfP2Sx1ixUDJZ0AWhHphEibvtbhIQ' . "\n" .
            '0F/UjVjCWGKsvHxRu3MVjitQywXK2zfMdHYkkl+roaSt2c+tlymiIhUklZ3MSafw' . "\n" .
            'LI00RDH5ihH/waj/uPxkb/JoQj3cgIt/ItDRt96Xx+iFELYKbp8AGWI58WNPvKvU' . "\n" .
            '07kYJD8Oew6lgZYk4rXkcu8CdHF1EJl4GxvVn5+PGregt0+0aUdgArdflJ/f7xpa' . "\n" .
            'pUmqQIa4Vf8g83JMiUy4syMPvlfxYiW66tSwuvPuwzxt+RUjHW4Y8NHvYe2IoQWt' . "\n" .
            'w+JvvXbiZaMmHFZGud6aGNIicdh4b/7RB2fX5jXWf+4ApG5djJ6q2x8D28gH810s' . "\n" .
            'J6tPwhLiOfYb6rYUxLlMYgaHMhCMYpuuuT3l64efJU7EvaDKYDRSsIUyqQuCPHTL' . "\n" .
            'mHS6ykLbgvi7LP9HyQzIYyld0l2QVKlfiyhyGkcdqC+dXJIKerg=' . "\n" .
            '-----END PUBLIC KEY-----';
        $this->assertSame($expected, $pk2->encodePem());

        $multibase = 'uEhCRMKElBrusZwHp_oz2RcIjGb3I_T4vXjLLWS2BxYdmfBWNNzAhy2cG0LH5Y2ETkVFnQkqxQ3MM-TnxHDsuz-fa7PTn7x_Pt-DPuFBldrCbSzMc5FPflqSLrhEGV13yjFbXJJdzoVpoCvJJw6ot1VtgLZGx8a5OEIpW-_nLKIHYhUeqfJk7yb8WB1-EYxuNkkKJ8RNaQ45Iy46pO7m84YPHc1d9spZJc-3vXg-panijPD66WFeH17IKrYN_DRKZQLLZB5360wFhoUiAvXe_IbJDjembRGKV381OSpkPnj6QGvg-4cwNdpc821ij7RoysRsov115NQa3mzBNw92DcGaCEoXSxelQ71-QqdErX2vaPKR6rQLiN7q7igD_DZ1r9mpnw168938z7eGuPiVU0O9dJee7oht0DpgEu4DSLDRwlWhCDUIRwEf_ebvEUe9D1SVsOV8-_5FZBxAmi3S5m5x9q7dyUz3NDmyUXrUgYsGrvhXPdtl711YNDplXntXl8x1ekSIVHRhJOJZHbPXhhGOmq6NhzarWE_hLEwXK_kFuWnS4jzx09DO-_aFfXNB0AGan5jnv0uoZGpu4FBgwagEVYWsh_EyYGpEIFVWXyAJkqueuahxJGEvx4UN1fC8W78KEiZdkBfcKpFJZGjlclSam6iIdQ0jJKHHfiRJ0NX2plRDVW2UsKxCGN8nb_1HFNuNyAlVuHsVrGZEzHYRQHurujif7nctHsXJaySm3Ubn9k5NY0PMXvIRUSJ4raFCro2kKd6zvMTs5rcwHtmo35RcmdJmqMae8-yuIO9bTAY9ht7u3n9BVN3zFQ7fy6nn7OH0KWDO2wHZjg7y6VR1G1N7SMzhz8ioi8ZciEXUk7Sn43O4_XJ2PbUr3-kmacnfo_A8X9XjD4yy5a3f6ihTqlAln-s3tunpk5jdskpSz5grLj4NeX6ODRXimNINgcEYx3GVtYo0MdxABU7uWTUoMpFgbsDFeT8zQOc2GbF61Hl3L6S_0OTOoII32lDukj7eSWCp4yUgzgwBKbrMfSafa9c-ONyuXoxRQBfzl1dqHI4BuJzwaita42SwPnIBRkxfjoOeu2xHZHoFKwkgWYsPhknfcUC61zTBqiz8CzVMJKjy3e3m0EXM56nPjF5RTfpDA1OQK-_k5E9LtlIDKJmowDB5X4VNod587hVKJbVadgXbBHCPZW7byRBGYiHRpoTb58F9XUFfk8JR6p7QOTXBErwpoq-oDX9mnQt4WTJ15P_hCVltMonJ4l4CEIff8ptjYgeIb23h1bHz9ksdYsVAyWdAFoR6YRIm77W4SENBf1I1YwlhirLx8UbtzFY4rUMsFyts3zHR2JJJfq6GkrdnPrZcpoiIVJJWdzEmn8CyNNEQx-YoR_8Go_7j8ZG_yaEI93ICLfyLQ0bfel8fohRC2Cm6fABliOfFjT7yr1NO5GCQ_DnsOpYGWJOK15HLvAnRxdRCZeBsb1Z-fjxq3oLdPtGlHYAK3X5Sf3-8aWqVJqkCGuFX_IPNyTIlMuLMjD75X8WIluurUsLrz7sM8bfkVIx1uGPDR72HtiKEFrcPib7124mWjJhxWRrnemhjSInHYeG_-0Qdn1-Y11n_uAKRuXYyeqtsfA9vIB_NdLCerT8IS4jn2G-q2FMS5TGIGhzIQjGKbrrk95euHnyVOxL2gymA0UrCFMqkLgjx0y5h0uspC24L4uyz_R8kMyGMpXdJdkFSpX4sochpHHagvnVySCnq4';
        $this->assertSame($multibase, $pk2->toMultibase());

        $multibase58 = 'zV9qAvt6HXRBzAqJMLG7mN8aWacsCuUUesp4yF6BnCNhZZ5GmgU8w4HNFNGVZsppLE1KRDFxVj2SuR7RRQicZC48WxmDAqCFnLw36uRjy4YUsvNQHNJE6hN6djFXk9Etv73n8fhuZr7cgp6kdwze28zzFnRvuNyJHGTap2X1i3SF4U7FMPLsFXrTDoHWAKuAHj8ysPnMKAuayYP4UHm3RK7f1YPFtVmpExmmKRJ6KN1bELKHS45nG1uZhfgGZYiru3iS2nA1UdKvnz9Javdq3DJPA1GLn84mTUQwpkiTmk67Xx5kxSw9yVMN9EMbvUtw4N6c77829EjEHRu42yQeh35RSA7pScutwDggsRrRAJCLjseoJ72NhuXxTs8Q4rwi45ZXkRxVmpMxiugmm9dd3D2XSUepehUswA9gE2fMpw9xhCsnF5vxXcKPt3GXi5CFmbyamPmzMAWYGMU1YpnkBXnCpU4E3s5qTbjeUsKviNb4cdP6axh8nJ9CRug7fDhXWRJnpGLbMXJKdvZbHgrPJVc7Q3HgKP4yW5ToJVLcDYgfGi9EKuDJNfwSzzACpZfJW6m6pdPb1yzPdB2PLW57TMeL5gm5BFDqnapagfAHmMuFJvvW5Vj8VKBHbdimJEtM5SJmwYwFoLYnEDxCyBjPmZWTb7tuyeq3ZbC4C1Fhjb2bkn9WYq181fo7K5L5QNxJtuh77qQEizkJykGvDLg3HDi1ZEfGGyZtMpbYU1Wx3K5C93jcFcBHA8nrsTMAhhzLfpfr3HRddGSBgCV4nLyGBfXJw5ZnFB93sPHiAigvBVNvTuBpfwbME7HQBd23xEYJHaXnCVCSvm4FYhxZRV5xpoygQ5zshbGPtUSoDqLavA8737UuNqo7hzg2n48ZFyD13pL4B498WQ5bkkasre29XgzwK8vN8no21DphBT9cqKhJhBcQYAzv2891EVXxeHrgJiv8mHEC9iLoJyHC165v6MUQcTFbprmrEcmjKrpDtMBENZoPXjQFk1j1KiUGqw6SZUGC9q1bdjMfCcPNwmiWdamDuzrbzjWfVh1FtqeVmPXv7c9DqJcYCQr9TkehVq4ffeHFg4Fewkvk4vrWR6f7uw9qDw2577QdxWREkDtNTdSMi6DZ2RA8YZCpRuee4NnvwVwG8CErPayyHA7gbRtQctSPgJTf4szvrETRAz5srj9fJEhtnmvggka5vEbkDq9ocwqroDgWqLdsNhdwpZFhRRsSHhDxcnJPosTq2pJ6i81fM7zRHmQJLEgQ2DteTRQFUo1bU4RPRfhG1VnRPFHH8cDhPMT6GEPZ4mNAGFWSaDefive1NiecD9XBJu5afYULKHutnZsozQPHjELzdLMrDvHpCUpbbu6pfuCQn4kSG3mwfnrA8hncwbxTZHh1ZWEdR6XbAUYC3ScLCrzaRSRrQfQM82VMt61TeD3UhoJazGwGFoTYUqQAtHtEyRUEt5YktqH7yj3YBnb8LST9heL6L8cogcaptNbyUxkw948AXmdcLF7NhiBNbPntnqvkQDgn7JjndE1mVc6kKKegwqDfedwqNf4Ygfvuh5KcU76pf2axA61UHz4rqc71XDrhoRUZLUVL21j63oYAhTUe4X2fjar8aNqZC1Ddrh6wQEkntD714nwu3GyiZ73vtsfRJkdQevSV9Tj2zasU7tRbRKpqK2gkHDRFDiQo8tWBcbb4zk1soxEoBec2Q5J5AsNQ5ZXaukMfiqdkh3J1bq6gTQrktbrQ85HzDWmrapdrCsLVMEyL9Accxec5CLQKU6LyHNUhXBm';
        $this->assertSame($multibase58, $pk2->toMultibase(true));

        $pk2_a = PublicKey::fromMultibase($multibase);
        $pk2_b = PublicKey::fromMultibase($multibase58);
        $this->assertSame($pk2->getBytes(), $pk2_a->getBytes());
        $this->assertSame($pk2->getBytes(), $pk2_b->getBytes());
    }
}
