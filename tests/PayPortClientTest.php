<?php

use PHPUnit\Framework\TestCase;
use PayPortNow\PayPortClient;

class PayPortClientTest extends TestCase
{
    public function testGeneratePaymentUrl()
    {
        $client = new PayPortClient("test_secret_key", "https://example.com/callback");

        $payload = [
            'orderId' => 'ORDER-123',
            'amount' => 100,
            'currency' => 'USDT'
        ];

        $url = $client->generatePaymentUrl($payload);

        $this->assertStringContainsString("https://localhost:7072?order=", $url);
    }
}
