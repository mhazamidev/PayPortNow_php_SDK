<?php

namespace PayPortNow;

class PayPortClient
{
    private $secret;
    private $callback;

    public function __construct($secretKey, $callbackUrl)
    {
        if (!isset($callbackUrl) || empty($callbackUrl)) {
            throw new \InvalidArgumentException("Missing or empty required field: callbackUrl");
        }

        if (!isset($secretKey) || empty($secretKey)) {
            throw new \InvalidArgumentException("Missing or empty required field: secretKey");
        }

        $this->secret = $secretKey;
        $this->callback = $callbackUrl;
    }

    public function generateSignature($json)
    {
        return base64_encode(hash_hmac('sha256', $json, $this->secret, true));
    }

    public function generatePaymentUrl($payload)
    {
        $requiredFields = ['orderId', 'amount', 'currency'];
        foreach ($requiredFields as $field) {
            if (!isset($payload[$field]) || empty($payload[$field])) {
                throw new \InvalidArgumentException("Missing or empty required field: $field");
            }
        }

        if (!is_numeric($payload['amount']) || $payload['amount'] <= 0) {
            throw new \InvalidArgumentException("Amount must be a positive number.");
        }

        $payload['secretKey'] = $this->secret;
        $payload['callbackUrl'] = $this->callback;

        $orderedPayload = [
            'OrderId' => $payload['orderId'],
            'Amount' => $payload['amount'],
            'Currency' => $payload['currency'],
            'SecretKey' => $payload['secretKey'],
            'CallbackUrl' => $payload['callbackUrl'],
            'Signature' => ''
        ];

        $json = json_encode($orderedPayload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $payload['signature'] = $this->generateSignature($json);

        list($key, $iv) = $this->generateKeyAndIV($this->secret);
        $encoded = $this->encryptData(json_encode($payload), $key, $iv);

        $order = $encoded . $this->secret;

        return "https://gate.payportnow.com?order=" . urlencode($order);
    }

    private function encryptData($plaintext, $key, $iv)
    {
        $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($ciphertext);
    }

    private function generateKeyAndIV($secret)
    {
        $hash = hash('sha256', $secret, true);
        $key = substr($hash, 0, 32);
        $iv = substr($hash, 0, 16);
        return [$key, $iv];
    }
}
