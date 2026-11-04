<?php

namespace Mainul\PasswordPolicy\Tests\Unit\Support;

use Mainul\PasswordPolicy\Support\Redactor;
use Mainul\PasswordPolicy\Tests\TestCase;

class RedactorTest extends TestCase
{
    public function test_masks_secret_keys_case_insensitively_and_recursively(): void
    {
        $out = Redactor::redact([
            'email'    => 'a@b.com',
            'Password' => 'hunter2',
            'nested'   => ['token' => 'abc', 'ok' => 1],
        ]);

        $this->assertSame('a@b.com', $out['email']);
        $this->assertSame(Redactor::MASK, $out['Password']);
        $this->assertSame(Redactor::MASK, $out['nested']['token']);
        $this->assertSame(1, $out['nested']['ok']);
    }
}
