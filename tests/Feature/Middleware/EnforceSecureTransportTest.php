<?php

namespace Mainul\PasswordPolicy\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Route;
use Mainul\PasswordPolicy\Tests\TestCase;

class EnforceSecureTransportTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware('password.secure')->get('/page', fn () => 'ok');
        Route::middleware('password.secure')->post('/login', fn () => 'ok');
    }

    protected function useProductionEnv(): void
    {
        $this->app['env'] = 'production';
        $this->beforeApplicationDestroyed(fn () => $this->app['env'] = 'testing');
    }

    public function test_not_enforced_outside_production(): void
    {
        $this->assertFalse($this->app->environment('production'));

        $this->get('http://localhost/page')->assertOk();
        $this->get('http://localhost/page?password=abc')->assertOk();
    }

    public function test_enforced_automatically_in_production(): void
    {
        $this->useProductionEnv();

        $this->get('http://localhost/page')->assertStatus(301)->assertRedirect('https://localhost/page');
        $this->get('https://localhost/page')->assertOk();
    }

    public function test_insecure_non_get_and_json_requests_are_rejected_in_production(): void
    {
        $this->useProductionEnv();

        $this->post('http://localhost/login')->assertStatus(403)->assertJson(['error' => 'https_required']);
        $this->getJson('http://localhost/page')->assertStatus(403)->assertJson(['error' => 'https_required']);
    }

    public function test_password_in_query_string_is_rejected_even_over_https(): void
    {
        $this->useProductionEnv();

        $this->get('https://localhost/page?password=abc')
            ->assertStatus(400)
            ->assertJson(['error' => 'password_in_query_string']);

        $this->get('https://localhost/page?user[Password]=abc')->assertStatus(400);
    }

    public function test_query_check_runs_before_redirect_so_password_is_not_echoed(): void
    {
        $this->useProductionEnv();

        $response = $this->get('http://localhost/page?password=abc');

        $response->assertStatus(400);
        $this->assertNull($response->headers->get('Location'));
    }

    public function test_config_can_force_enforcement_outside_production(): void
    {
        config()->set('password-policy.tls.enforce', true);

        $this->get('http://localhost/page')->assertStatus(301);
    }

    public function test_config_can_disable_enforcement_in_production(): void
    {
        $this->useProductionEnv();
        config()->set('password-policy.tls.enforce', false);

        $this->get('http://localhost/page')->assertOk();
    }
}
