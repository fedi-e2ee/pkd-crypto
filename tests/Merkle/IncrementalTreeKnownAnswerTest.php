<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests\Merkle;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Merkle\{
    IncrementalTree,
};
use PHPUnit\Framework\Attributes\{
    CoversClass,
    DataProvider
};
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(IncrementalTree::class)]
class IncrementalTreeKnownAnswerTest extends TestCase
{
    public static function merkleKnown(): array
    {
        return [
            // Trivial cases: empty
            [
                'blake2b',
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                []
            ],
            [
                'sha256',
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                []
            ],
            [
                'sha384',
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                []
            ],
            [
                'sha512',
                'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                []
            ],
            // simple nodes
            [
                'blake2b',
                'pkd-mr-v1:DOm7WoZrMtqbvt9jqXXOhRZia3lrXOrkC541PCiknd8',
                [
                    'pkd-mr-v1:cjQILh3QtewKzXGHXWHJ83SvMMEAvE3nqk6z8Vu-1oY' => 'a',
                    'pkd-mr-v1:7mFmJaWQFnvEs9xwOrTz8t3svua50F_ukoHwIEbmCC4' => 'b',
                    'pkd-mr-v1:FzIdtRwe8-wfd-JxqjALTlxgkXCLy6N-RgJXdKJhQu4' => 'c',
                    'pkd-mr-v1:QhNgpgmYA7Rl3_UkbLFkwrb_rFTxfOzAT6e_4lYeGAQ' => 'd',
                    'pkd-mr-v1:V9NmIuP5ANrdMn-xCLYuKCy49lIl_yR0nfeNCRdsHQ0' => 'e',
                    'pkd-mr-v1:pPfLZN5vnnKtp3MydlFAIR-55a8x10V_ikz1xAYDy3Q' => 'f',
                    'pkd-mr-v1:DOm7WoZrMtqbvt9jqXXOhRZia3lrXOrkC541PCiknd8' => 'g',
                ]
            ],
            [
                'sha256',
                'pkd-mr-v1:4Gn8EuIxzP1FFr8WF5Rfs8zVzIkQ2S1iZSifCI93f90',
                [
                    'pkd-mr-v1:Aippeebat6pa5MPl5F9-l3ESp-Y1k4INvsHsc4ok-Tw' => 'a',
                    'pkd-mr-v1:sTeYX_SE-2ANuTEHx3sDZcgNePW0Kd7Q_Zc2HQd5mes' => 'b',
                    'pkd-mr-v1:NmQuc8JUCrEh46a_lUWwokmCzYMOsT080Z3jzmwCHsE' => 'c',
                    'pkd-mr-v1:MzdqO9Y-mZNwioTd_mworli4NQXdH-1xG9kk7FpiOfA' => 'd',
                    'pkd-mr-v1:_hSlQm-9cMD6c_UjQq_tDaC9I8SDhmLM9riKMHDq2Xs' => 'e',
                    'pkd-mr-v1:4Gn8EuIxzP1FFr8WF5Rfs8zVzIkQ2S1iZSifCI93f90' => 'f',
                ]
            ],
            [
                'sha384',
                'pkd-mr-v1:Yn3Wqu2wQaPAou2FCub9QtWKMoZBjH7smLQqJnTQwNQZCFR0APgEV8HoFC4CXXEJ',
                [
                    'pkd-mr-v1:9Qd8S24yiyHi8hGSd22vlmDOrq9AoXlrWL2VALNq_yy1rNedJ4n4kVQYGDFSM_9s' => 'a',
                    'pkd-mr-v1:JunYUN2CC1vcIiLcxXSWjv0uosyqtpS0RMSPR50xw5XWqNqd_oZc7aHjqJrDpkRw' => 'b',
                    'pkd-mr-v1:9Vi-JGSTjNMmbnolzIdv1ml3aMio0xL7cBPQBquYaGk32JrZJUe0Ka1pJkwR_FOL' => 'c',
                    'pkd-mr-v1:RbDLKSG-nJN_-x5PqHDQN2J4DVaxwLMrgF0LqCawkV7T6znmy3iDG-TXJ32G4Ccc' => 'd',
                    'pkd-mr-v1:NWgj9ZkVvEPSYjVSNgzhQ45j_NQiVmDtmIFNYn15_qp9tH4xwOm_QuqYOEBzykEz' => 'e',
                    'pkd-mr-v1:Yn3Wqu2wQaPAou2FCub9QtWKMoZBjH7smLQqJnTQwNQZCFR0APgEV8HoFC4CXXEJ' => 'f',
                ]
            ],
            [
                'sha512',
                'pkd-mr-v1:gxKBPIsnaX256zE_yjEv9UqfVBHdcC4W3eCBwEk4VqoGJNRonG83Vp6d0-KSCVLGVe1GpOdbBTT8vops_bytLQ',
                [
                    'pkd-mr-v1:Axq5_1li6BE5ppACFpRfxYSrGGrrG_NJjGYbl2pzk6-UtrzJeE9-jLdbBx3mD5_aBtRN3VYeU-M0OFfuogiSFw' => 'a',
                    'pkd-mr-v1:S0bfmLcQSXjlihTtPV_ruJuyMn_85DB7VSVK6LJudr8lHex-oREVAqFC4urfWo673s5LOlGcfPPHgRRPKjjyzw' => 'b',
                    'pkd-mr-v1:gxKBPIsnaX256zE_yjEv9UqfVBHdcC4W3eCBwEk4VqoGJNRonG83Vp6d0-KSCVLGVe1GpOdbBTT8vops_bytLQ' => 'c',
                ]
            ],
            // Repeated empty string
            [
                'sha256',
                'pkd-mr-v1:3rguFVlU1r4UWSxmzPeh7OGT7uvNq690e5H0RRnwn0c',
                [
                    'pkd-mr-v1:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0' => '',
                    'pkd-mr-v1:_kPWavpKmlxPnJ2on0_7UmNcjzQuf_tzHWjjbFmCByo' => '',
                    'pkd-mr-v1:SDdmXf5kCjcOdJbGkZh1YtAkYhQsXzT1nhhZEaEjcOo' => '',
                    'pkd-mr-v1:3rguFVlU1r4UWSxmzPeh7OGT7uvNq690e5H0RRnwn0c' => '',
                ]
            ],
            // Recursion from empty string
            [
                'sha256',
                'pkd-mr-v1:OyYryxgdATAHSMRiu_YJ348eSKJ6_pQT6PTIgRF8Fbc',
                [
                    'pkd-mr-v1:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0' =>
                        '',
                    'pkd-mr-v1:hfm9Wl1aB4GceoKV28mDbTxjapw7vxODU7UH57hk6iU' =>
                        'pkd-mr-v1:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0',
                    'pkd-mr-v1:VqbotXwXTAOtvjQw4T9pwc1Ig3WvoGJwzarjDUfWjzE' =>
                        'pkd-mr-v1:hfm9Wl1aB4GceoKV28mDbTxjapw7vxODU7UH57hk6iU',
                    'pkd-mr-v1:TygUKY6GRzx_eAG00GbD-y3z2BkYvRLrThAuAL3B40w' =>
                        'pkd-mr-v1:VqbotXwXTAOtvjQw4T9pwc1Ig3WvoGJwzarjDUfWjzE',
                    'pkd-mr-v1:OyYryxgdATAHSMRiu_YJ348eSKJ6_pQT6PTIgRF8Fbc' =>
                        'pkd-mr-v1:TygUKY6GRzx_eAG00GbD-y3z2BkYvRLrThAuAL3B40w',
                ]
            ],
            [
                'sha256',
                'pkd-mr-v1:8WEURFuzEK8qsBO6nAlsE_TucmuZAdxX49S-req81T4',
                [
                    'pkd-mr-v1:q0fFfrhVM6ybbDadUJFzUEJ1AyKinX5bR6m0jVP1Elw' => str_repeat("\xFF", 9),
                    'pkd-mr-v1:0HeTeSCNgDGshPvQ4kbkbK7HqdkZlZ6TnZXkZfXv1EA' => str_repeat("\x00", 11),
                    'pkd-mr-v1:ULXCO2XzSh32CYtyRVBiB15WpPkcG54omjdropy53fU' => str_repeat("\x41", 12),
                    'pkd-mr-v1:TQuxql8pmsHaR7sF9NbGibJB0AvmpRuTfVKYLLTuuKA' => str_repeat("\x7E", 13),
                    'pkd-mr-v1:-hpCeXj7NH0VA2gP1QU4ogdkc4LJn19ZslezW1miC28' => str_repeat("\xFF", 14),
                    'pkd-mr-v1:t-jcqzFILHqd8WSj4PnJWBNX8ZCauTz4FW8xfUceObs' => str_repeat("\x06", 15),
                    'pkd-mr-v1:mlup6W7YOYrpFpbGx1qsTLN5t3085fg0wNZHuxIRAUw' => str_repeat("\x07", 16),
                    'pkd-mr-v1:Ah-uR7_NrsF-TTYZbcZBo6gslCfaj_iwvAyfvRaC6Ck' => str_repeat("\x08", 17),
                    'pkd-mr-v1:U-ZBlp8pcmItTDTlZGK6jtZR1umyet3JdylhgQA6xbU' => str_repeat("\x09", 18),
                    'pkd-mr-v1:9NQcIl0zwkSCAbCBcy4U_nI9s5rDqRhICMG6BcXJ_XU' => str_repeat("\x0A", 30),
                    'pkd-mr-v1:WN1v5x4bf9WUiRmfSVq3xFP2SlWorUlBIRFo3C9XQo8' => str_repeat("\x0B", 31),
                    'pkd-mr-v1:8WEURFuzEK8qsBO6nAlsE_TucmuZAdxX49S-req81T4' => str_repeat("\x0C", 31),
                ]
            ]
        ];
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("merkleKnown")]
    public function testKnownAnswers(
        string $hashAlg,
        string $finalRoot,
        array $mapping,
    ): void {
        $tree = new IncrementalTree([], $hashAlg);
        $index = 0;
        foreach ($mapping as $expectedRoot => $additionalLeaf) {
            $tree->addLeaf($additionalLeaf);
            $intermediary = $tree->getEncodedRoot();
            $this->assertSame($expectedRoot, $intermediary, $hashAlg . ' index = ' . $index);
            ++$index;
        }
        $this->assertSame($finalRoot, $tree->getEncodedRoot(), 'final root');
    }
}
