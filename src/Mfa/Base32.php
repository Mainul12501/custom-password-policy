<?php

namespace Mainul\PasswordPolicy\Mfa;

use InvalidArgumentException;

/** RFC 4648 Base32 (the encoding authenticator apps use for secrets). */
class Base32
{
    protected const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $binary): string
    {
        $bits = '';
        foreach (str_split($binary) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $out;
    }

    public static function decode(string $encoded): string
    {
        $encoded = strtoupper(str_replace([' ', '-', '='], '', $encoded));
        $bits = '';

        foreach (str_split($encoded) as $char) {
            $pos = strpos(self::ALPHABET, $char);

            if ($pos === false) {
                throw new InvalidArgumentException('Invalid Base32 character.');
            }

            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }

        return $out;
    }
}
